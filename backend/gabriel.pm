#    Copyright 2014 Cert.gov.ge <cert@dea.gov.ge>
#
#    This file is part of Gabriel.
# 
#    Gabriel is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Gabriel is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Gabriel.  If not, see <http://www.gnu.org/licenses/>.
#    You should have received a copy of the GNU General Public License
#
################################################################################
#
#    This plugin detects DDoS attacks and displays the result for each timeslot.
#    several indices are counted for each timeslot data and are saved in
#    the database. such as: total bytes sent and received during each timeslot,
#    total packets, number of similar packets (two packets are assumed similar
#    if they are of the same size) and the percentage of the most often 
#    repeated packet.
#    DDoS is detected if the following two conditions are met:
#        1. total bytes in this flow are greater than the average number
#        of total bytes during last $interval period **times** some coefficient.
#        2. percentage of similar packets in this flow is greater than the
#        average number of such percentage during last $interval period
#        **PLUS** some coefficient;
#    if either of the above two conditions are not met, no DDoS is detected;
#    
#    This is mostly the testing release, so these coefficients may be
#    changed according to your needs. see ($INTERVAL, $PERCENTAGE_COEFFICIENT
#    and BYTE_COEFFICIENT) below.
#    Increase $INTERVAL if you want to consider older flows when detecting DDoS.
#    Increase $PERCENTAGE_COEFFICIENT and $BYTE_COEFFICIENT if a normal flow is 
#    detected as an attack, or decrease them if some attacks are not detected.
#    
#    in the case of bugs, misbehaviour, problems or ideas, write at
#    cert@dea.gov.ge
#

package gabriel;

# highly recommended for good style Perl programming
use strict;
use Sys::Syslog;
use List::MoreUtils qw(firstidx);
use lib '/usr/local/nfsen/libexec/';
use NfProfile;
my $dbh;

my $DSN = 'dbi:mysql:gabriel';
my $DB_USER = 'root';
my $DB_PASS = 'dbpass';
use DBI;

# average number of bytes in each timeslot and
# average percentage of most popular packet count in each timeslot
# is counted during the last $interval period.
# if most popular packet count in a given timeslot is $PERCENTAGE_COEFFICIENT bigger
# then the average of it during the last $interval period, 
# and also total bytes sent and received in this timeslot
# is $BYTE_COEFFICIENT **times** bigger than the average of it, 
# attack is detected.
# change these variables according to your needs.
my $INTERVAL = 30; # days
my $PERCENTAGE_COEFFICIENT = 40;
my $BYTE_COEFFICIENT = 3;
# if (byte_count_in_this_timeslot > average_byte_count_in_last_$interval_period * $BYTE_COEFFICIENT) {
#	if (most_popular_packet_percentage_in_this_timeslot > average_percentage_in_last_$interval_period + $PERCENTAGE_COEFFICIENT) {
# 		ATTACK = 1;
#	}
# } 

# This string identifies the plugin as a version 1.3.0 plugin.
our $VERSION = 130;

my $nfdump;

our %cmd_lookup = (
    'getdata' => \&get_data,
    );


sub get_data {
    my $socket  = shift;        # scalar
    my $opts    = shift;        # reference to a hash

    # error checking
    if ( !exists $$opts{'index'}) {
        Nfcomm::socket_send_error($socket, "Missing value");
        return;
    }

    # retrieve values passed by frontend
    my $index = $$opts{'index'};
    my $start_date = $$opts{'start_date'};
    my $start_time = $$opts{'start_time'};
    my $end_date = $$opts{'end_date'};
    my $end_time = $$opts{'end_time'};
    my $n_sources = $$opts{'n_sources'};
    my $attack_only = $$opts{'attack'};

    my $query1 = '1';
    if ($start_date) {
        my $start_datetime = $start_date . " " . $start_time;
        $query1 = "gabriel.main.timeslot >= \'$start_datetime\'";
    }
    my $start_datetime = 0;
    if ($start_date) {
        $start_datetime = $start_date . " " . $start_time;
    }
    
    my $query2 = '1';
    if ($end_date) {
        my $end_datetime = $end_date . " " . $end_time;
        $query2 = "gabriel.main.timeslot <= \'$end_datetime\'";
    }


    my $query3 = 'gabriel.main.source in (';
    for (my $i = 0; $i < $n_sources; $i++) {
        my $key = 'source_' . $i;
        $query3 .= '\'';
        $query3 .= $$opts{$key};
        $query3 .= '\'';
        if ($i < $n_sources - 1) {
            $query3 .= ", ";
        } else {
            $query3 .= ")"
        }
    }
    if ($n_sources == 0) {
	$query3 = 0;
    }

    my $query4 = 1;
    if ($attack_only == 1) {
        $query4 = "gabriel.main.under_attack = 1";
    }

    my $dbh = DBI->connect($DSN, $DB_USER, $DB_PASS) or
        die $DBI::errstr;
    my $query = "(SELECT * FROM gabriel.main where $query1 and $query2 and $query3 and $query4 ORDER BY id DESC LIMIT $index) order by id ASC LIMIT 1;";
    syslog('debug', "query is: $query\n");
    my $sth = $dbh->prepare($query);

    $sth->execute();
    my $n_rows = $sth->rows();
    my ($id, $source, $timeslot, $attack, $total_bytes, $popular_packet_count, $total_packets,
        $popular_packet_size, $popular_packet_percentage) = $sth->fetchrow();


    # Prepare answer
    my %args;
    $args{'timeslot'} = $timeslot;
    $args{'source'} = $source;
    $args{'attack'} = $attack;
    $args{'total_bytes'} = $total_bytes;
    $args{'popular_packet_count'} = $popular_packet_count;
    $args{'total_packets'} = $total_packets;
    $args{'popular_packet_size'} = $popular_packet_size;
    $args{'popular_packet_percentage'} = $popular_packet_percentage;
    $args{'id'} = $id;


    Nfcomm::socket_send_ok($socket, \%args);
    $sth->finish();
    $dbh->disconnect();

}

#
# The Init function is called when the plugin is loaded. It's purpose is to give the plugin
# the possibility to initialize itself. The plugin should return 1 for success or 0 for
# failure. If the plugin fails to initialize, it's disabled and not used. Therefore, if
# you want to temporarily disable your plugin return 0 when Init is called.
#
sub Init {
    syslog('debug', "gabriel started\n");
    $nfdump = "$NfConf::PREFIX/nfdump";
    return 1;
}

sub count_bytes {

    my $netflow_sources = shift;
    my $timeslot = shift;


    syslog('debug', "netflow sources is: $netflow_sources");
    my $str = "$nfdump -M $netflow_sources -r nfcapd.$timeslot -A proto -o  csv";
    my @output;
    @output = `$nfdump -M $netflow_sources -r nfcapd.$timeslot -A proto -o  csv`;
    my $len = @output;

    syslog('debug', "output: @output");
    my $statistics_idx = firstidx {$_ eq "Summary\n"} @output;
    $statistics_idx = 7;
    my $headers_index = $statistics_idx + 1;
    my @headers_arr = split(',', $output[$headers_index]);
    my @values_arr = split(',', $output[$headers_index + 1]);
    my $index = firstidx {$_ eq "bytes"} @headers_arr;
    my $res = $values_arr[$index];

    return $res;
}


sub count_popular_packets {
    my $netflow_sources = shift;
    my $timeslot = shift;

    my @output = `$nfdump -M $netflow_sources -r nfcapd.$timeslot -o "fmt:%bpp %pkt"`;
    my $len = @output;
    my $i = 1;
    my %hashmap;
    while ($i < $len - 4) {
        my $line = $output[$i];
        my @line_arr = split(' ', $line);
        my $bytes = $line_arr[0];
        my $packets = $line_arr[1];

        if (exists $hashmap{$bytes}) {
            $hashmap{$bytes} = $hashmap{$bytes} + $packets;
        } else {
            $hashmap{$bytes} = $packets;
        }
        $i++;
    }
    my $total_packets = 0;
    my $popular_packet_count = 0;
    my $popular_packet_size = 0;
    while (my ($key, $val) = each %hashmap) {
        if ($val > $popular_packet_count) {
            $popular_packet_count = $val;
            $popular_packet_size = $key;
        }
        $total_packets += $val;
    }
    return ($total_packets, $popular_packet_count, $popular_packet_size);
}


# returns number of total rows in database
# from this $source, during last $interval period,
# where attack was not happening.
sub count_records {
    my $dbh = shift;
    my $source = shift;
    my $interval = shift;

    my $query = "SELECT count(*) FROM gabriel.main where (gabriel.main.under_attack != 1 and gabriel.main.source = \"$source\" and gabriel.main.timeslot > (DATE_SUB(now(), INTERVAL $interval DAY)));";
    my $sth = $dbh->prepare($query);
    $sth->execute();
    my $n_rows = $sth->rows();
    my $total_records = $sth->fetchrow();
    return $total_records;
}

# Periodic data processing function
#	input:	hash reference including the items:
#			'profile'		profile name
#			'profilegroup'	profile group
#			'timeslot' 		time of slot to process: Format yyyymmddHHMM e.g. 200503031200
sub run {
    my $argref = shift;

    my $profile = $$argref{'profile'};
    my $profilegroup = $$argref{'profilegroup'};
    my $timeslot = $$argref{'timeslot'};


    syslog('debug', "gabriel run: Profilegroup $profilegroup, Profile: $profile, Time: $timeslot");
    my %profileinfo     = NfProfile::ReadProfile($profile, $profilegroup);
    my $profilepath     = NfProfile::ProfilePath($profile, $profilegroup);
    my $all_sources     = join ':', keys %{$profileinfo{'channel'}};
    my $netflow_sources = "$NfConf::PROFILEDATADIR/$profilepath/$all_sources";

    syslog('debug', "all sources: $all_sources");

    my @sources = keys %{$profileinfo{'channel'}};
    my $dbh = DBI->connect($DSN, $DB_USER, $DB_PASS) or
        die $DBI::errstr;

    for (my $i = 0; $i < @sources; $i++) {
        my $key = $sources[$i];
        my $source = "$NfConf::PROFILEDATADIR/$profilepath/$key";
        my $total_bytes = count_bytes($source, $timeslot);

        my $under_attack = 0;


        my ($total_packets, $popular_packet_count, $popular_packet_size) = count_popular_packets($source, $timeslot);
        if ($total_packets == 0) {
            next;
        }
        my $percentage = $popular_packet_count * 100 / $total_packets;

        my $query;
        my $avg_bytes;
        my $avg_percentage;
        if (count_records($dbh, $key, $INTERVAL) >= 1) {
            $query = "SELECT AVG(gabriel.main.total_bytes) FROM gabriel.main where (gabriel.main.under_attack != 1 and gabriel.main.source = \"$key\" and gabriel.main.timeslot > (DATE_SUB(now(), INTERVAL $INTERVAL DAY)));";
            my $sth = $dbh->prepare($query);
            $sth->execute();
            my $n_rows = $sth->rows();
            $avg_bytes = $sth->fetchrow();

            $query = "SELECT AVG(gabriel.main.popular_packet_percentage) FROM gabriel.main where (gabriel.main.under_attack != 1 and gabriel.main.source = \"$key\" and gabriel.main.timeslot > (DATE_SUB(now(), INTERVAL $INTERVAL DAY)));";
            $sth = $dbh->prepare($query);
            $sth->execute();
            $n_rows = $sth->rows();
            $avg_percentage = $sth->fetchrow();



            if ($total_bytes > $avg_bytes * $BYTE_COEFFICIENT && $percentage >= $avg_percentage + $PERCENTAGE_COEFFICIENT) {
                $under_attack = 1;
            }
        }


        my $year = substr $timeslot, 0, 4;
        my $month = substr $timeslot, 4, 2;
        my $day = substr $timeslot, 6, 2;
        my $hour = substr $timeslot, 8, 2;
        my $minute = substr $timeslot, 10, 2;

        my $datetime = "$year-$month-$day-$hour-$minute";
        my $str = "insert into gabriel.main (source, timeslot, under_attack, total_bytes, popular_packet_count, total_packets, popular_packet_size, popular_packet_percentage) VALUES(\"$key\", \"$datetime\", $under_attack, $total_bytes, $popular_packet_count, $total_packets, $popular_packet_size, $percentage)";
        syslog('debug', "gabriel debug: index is $i db query is $str");
	for (my $i = 0; $i < 1; $i++) {
	    $dbh->do($str);
	}

    }

    $dbh->disconnect();
    syslog('debug', "disconnected.");

    return;

}

#
# The Cleanup function is called, when nfsend terminates. It's purpose is to give the
# plugin the possibility to cleanup itself. It's return value is discard.
sub Cleanup {
    syslog("info", "gabriel Cleanup");
}


1;
