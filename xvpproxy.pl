#!/usr/bin/env perl
# Gets dom0s from nagios and acts as a WS proxy between noVNC and XVP
#
# https://github.com/jberger/Mojo-Websockify
# http://xapi-project.github.io/xen-api/
# https://wiki.openstack.org/wiki/VNCConsoleCleanup
# https://tools.ietf.org/html/rfc6143

use Mojolicious::Lite;
use DBIx::Connector;

#app->attr('novnc_url' => 'http://kanaka.github.io/noVNC/noVNC/vnc_auto.html');
app->attr('novnc_url' => '/noVNC/vnc_auto.html');
app->attr('lastvm' => 'sealand');
app->attr('dbname' => app->home->to_string.'/database.db');
app->static->paths->[0] = app->home->to_string.'/';

# Rewrite if behind proxy pass.
app->hook('before_dispatch' => sub {
    my $c = shift;
    app->attr('base' => '');
    if ($c->req->headers->header('X-Forwarded-For')) {
        my $base = $c->req->url->host;
        $c->req->url->base->path->parse($base);
        app->attr('base' => "/$base");
        $c->app->log->debug("Request under proxy pass, app->base = '".app->base()."'");
    }
});

helper api_call => sub {
  my $args;
  (my $c, my $cb, $args->{hostname}, $args->{method}, @{$args->{params}} ) = @_;
  $args->{params_string} .= '<param><value><string>'.$_.'</string></value></param>' foreach @{ $args->{params} };
  $c->ua->post(  $args->{hostname}
              => { Content_Type => 'text/xml' }
              => '<?xml version="1.0" encoding="us-ascii"?><methodCall><methodName>'.$args->{method}.'</methodName><params>'.$args->{params_string}.'</params></methodCall>'
              => sub { my ($ua, $tx) = @_;
                       $tx->{args} = $args;
                       $c->$cb($tx);
                     }
              );
};

# Database helper methods
helper connector => sub {
  state $db = DBIx::Connector->new('dbi:SQLite:'.app->dbname()) or die "Could not connect";
};

helper db => sub { shift->connector->dbh };

helper create_table => sub {
  my $c = shift;
  $c->app->log->info("Creating table 'pools'");
  $c->db->do('CREATE TABLE pools (name TEXT NOT NULL UNIQUE, ip TEXT NOT NULL);');
};

helper select => sub {
  my $c = shift;
  my $sth = eval { $c->db->prepare('SELECT * FROM pools') } || return undef;
  $sth->execute;
  return $sth->fetchall_arrayref;
};

helper insert => sub {
  my $c = shift;
  my $sth = eval { $c->db->prepare('INSERT OR IGNORE INTO pools VALUES (?,?)') } || return undef;
  $sth->execute(@_);
  return 1;
};

# Create BBDD/table if it doen't exist
app->select || app->create_table;

# Fetch Dom0s info from Nagios
websocket '/fetch' => sub {
  my $c = shift;
  $c->app->log->info("Fetching...");
  $c->on( json => sub {
    my ($ws, $row) = @_;
    $c->ua->get('http://user:pass@host/nagios/cgi-bin/config.cgi?type=services' => sub {
      my ($ua, $tx) = @_;
      my %tmphash = ();
      my $body = $tx->res->body;
      $tmphash{$1} = $2 while $body =~ /check_xen!([^!]+)!([^!]+)!HOSTS/sgi;
      map{ $c->insert($_, $tmphash{$_}) } keys %tmphash;
      $ws->send({ json => 'Got '.(scalar keys %tmphash).' pools from nagios.' });
    });
  });
};

# Ask the Dom0s for a RFB console and get up the proxy
websocket '/*target' => sub {
  my $c = shift;
  $c->render_later;
  $c->inactivity_timeout(300);
  $c->on(finish => sub { warn 'websocket closing' });
  $c->tx->with_protocols('binary');
  my $tx = $c->tx;

  my $target = $c->stash('target');
  $c->app->log->info("[0] Target is '$target'");

  $c->delay(
    sub {
      my $delay = shift;
      my $rows = $c->select;
      foreach my $host (@$rows) {
        $c->app->log->info("[1] Authenticating to $host->[0]");
        $c->api_call($delay->begin, $host->[0], 'session.login_with_password', 'root', $host->[1]);
      }
    },
    sub {
      my ($delay, @results) = @_;
      foreach my $res (@results) {
        my $token = $res->res->dom->find('member value')->last->text;
        $c->app->log->info("[2] Got token '$token from ".$res->original_remote_address);
        $delay->data->{$res->original_remote_address}->{token} =  $token;
        $c->api_call($delay->begin, $res->original_remote_address, 'VM.get_by_name_label', $token, $target );
      }
    },
    sub {
      my ($delay, @results) = @_;
      foreach my $res (@results) {
        my $body = $res->res->body;
        my ($vmref) = $body =~ />(OpaqueRef:[^<]+)</;
        next unless $vmref;
        next if $delay->data->{found};
        $delay->data->{found}++;
        $c->app->log->info("[3] Found '$target' with vmref '$vmref' on ".$res->original_remote_address);
        my $token = $delay->data->{$res->original_remote_address}->{token};
        $c->api_call($delay->begin, $res->original_remote_address, 'VM.get_consoles', $token, $vmref );
      }
      # Return error if we got no results.
      $tx->finish(4500, "Got no results for '$target'") unless $delay->data->{found};
    },
    sub {
      my ($delay, @results) = @_;
      foreach my $res (@results) {
        my $token = $delay->data->{$res->original_remote_address}->{token};
        foreach my $conref ($res->res->dom->find('data value')->map('text')->each) {
          $c->app->log->info("[4] Got conref '$conref' on '$target'");
        $c->api_call($delay->begin, $res->original_remote_address, 'console.get_record', $token, $conref );
        }
      }
    },
    sub {
      my ($delay, @results) = @_;
      foreach my $res (@results) {
        my $record;
        $res->res->dom->find('value')->each(sub {$record->{$_->previous->text} = $_->text});
        $c->app->log->info("[5] Got the $record->{protocol} url '$record->{location}'");
        next unless $record->{protocol} eq 'rfb';
        $record->{token} = $delay->data->{$res->original_remote_address}->{token};
        ($record->{address}) = $record->{location} =~ m|://([^/]+)/|;
        $delay->pass($record);
      }
    },
    sub {
      my ($delay, @results) = @_;
      foreach my $res (@results) {
        my $call = "CONNECT /console?uuid=$res->{uuid}&session_id=$res->{token} HTTP/1.0";
        $c->app->log->info("[6] Connect string is: '$call'");
        Mojo::IOLoop->client(address => $res->{address}, port => 80, sub {
          my ($loop, $err, $tcp) = @_;
          $tx->finish(4500, "TCP connection error: $err") if $err;

          $tcp->on(error => sub { $tx->finish(4500, "TCP error: $_[1]") });

          # This method will only trigger once so we can deal with the RVP response.
          $tcp->once(read => sub {
            my ($tcp, $bytes) = @_;
            my $length = length($bytes);
            $c->app->log->info("[7] Auth response:\n${bytes}> $length bytes");
            # Bail out unless we got a 200 status code.
            $tx->finish(4500, $bytes) unless substr($bytes, 9, 3) eq '200';
            # Workaround for getting the ProtocolVersion Handshake with the response.
            # The standard reply is 78 bytes long, the Handshake is 12.
            $tx->send({binary => substr($bytes, -12)}) if $length == 90;
            $tcp->timeout(300);
            # Suscribe to the read event for the RFB stream.
            $tcp->on(read => sub {
              my ($tcp, $bytes) = @_;
              $tx->send({binary => $bytes});
            });
          });

          $tx->on(binary => sub {
            my ($tx, $bytes) = @_;
            $tcp->write($bytes);
          });

          $tx->on(finish => sub {
            $tcp->close;
            undef $tcp;
            undef $tx;
          });

          # Perform the XVP auth call
          $tcp->write("$call\r\n\r\n");
        });
      }
    }
  );
};

# Base route
any '/' => sub {
  my $c = shift;
  my $host = $c->tx->local_address;
  my $port = $c->tx->local_port;
  my $novnc_url = app->novnc_url()."?autoconnect=true&host=$host&port=$port&path=";
  say app->lastvm();
  $c->render('index', novnc_url => $novnc_url);
};

app->start;

__DATA__

@@ index.html.ep
<!DOCTYPE html>
<html>
<head>
  <title>noVNC Proxy</title>
  %= stylesheet 'https://cdnjs.cloudflare.com/ajax/libs/semantic-ui/2.2.4/semantic.min.css'
  <style type="text/css">
    #container { height: 100%; }
    #overlay {
      position: fixed;
      bottom: 5px;
      left: 5px;
      }
    #vnc {
      height: 100%;
      width: 100%;
      border: 0;
    }
  </style>
</head>
<body>
  <div id="container">
    <div id="overlay">
      <div class="ui mini right labeled input">
        <a id="fetch" class="ui black label">Fetch</a>
        <input id="choose" placeholder="Enter a Xen VM name..." type="text">
        <a id="connect" class="ui black tag label">Connect</a>
      </div>
    </div>
    <iframe id="vnc" src="<%= $novnc_url.app->lastvm() %>"></iframe>
  </div>
  %= javascript 'https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js'
  %= javascript begin
    $('#fetch').click(function(){
      if (!("WebSocket" in window)) {
        alert('Your browser does not support WebSockets!');
      }
      var ws = new WebSocket("<%== url_for('fetch')->to_abs %>");
      ws.onopen = function () {
        ws.send(0);
      }
      ws.onmessage = function(e){
        var data = JSON.parse(e.data);
        alert(e.data);
      }
    });
    $('#vnc').focus();
    $('#choose').val('');
    $('#connect').click(function(){
      window.open("<%== $novnc_url %>" + $('#choose').val());
    });
  %= end
</body>
</html>
