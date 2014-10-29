<script src="https://code.jquery.com/jquery-latest.min.js"> </script>
<script src="plugins/gabriel.js">  </script>
<?php
/*
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
*/

/*
 * Frontend plugin: gabriel
 *
 * Required functions: gabriel_ParseInput and gabriel_Run
 *
 */

/*
 * gabriel_ParseInput is called prior to any output to the web browser
 * and is intended for the plugin to parse possible form data. This
 * function is called only, if this plugin is selected in the plugins tab.
 * If required, this function may set any number of messages as a result
 * of the argument parsing.
 * The return value is ignored.
 */
function gabriel_ParseInput( $plugin_id ) {
//        SetMessage('error', "Error set by gabriel!");
//        SetMessage('warning', "Warning set by gabriel!");
//        SetMessage('alert', "Alert set by gabriel!");
//        SetMessage('info', "Info set by gabriel!");

} // End of gabriel_ParseInput

function draw_search($plugin_id)
{
        $sources = array();
        foreach ($_SESSION['profileinfo']["channel"] as $channel) {
                array_push($sources, $channel["name"]);
        }


?>
        <form name="search" action="nfsen.php" method="get">
        <span> start date: </span>
        <input type="date" onchange="values_changed()" name="start_date" id="start_date">
        <span> start time: </span>
        <input type="time" onchange="values_changed()" name="start_time" id="start_time">
        <br>
        <span> end date: </span>
        <input type="date" onchange="values_changed()" name="end_date" id="end_date">
        <span> end time: </span>
        <input type="time" onchange="values_changed()" name="end_time" id="end_time">
        </br>
        <input type="hidden" name="submitted" value="true">
<?php
        for ($i = 0; $i < count($sources); $i++) {
 ?>         
        <span> <?=$sources[$i]?>: </span>
 <input type="checkbox" id="<?=$sources[$i]?>" checked="true" name="<?=$sources[$i]?>" onchange="checkbox_changed('<?=$sources[$i]?>')">
<?php
        }
?>
        <br>
        <span> attack only: </span>
        <input type="checkbox" id="attack" name="attack" onchange="values_changed()">
        <br>
        <br>
        <input type="submit" value="Submit">
        
        </form>
<?php
}

function update_session_variables($plugin_id)
{
        if (!$_SESSION['plugin'][$plugin_id]) {
                $_SESSION['plugin'][$plugin_id]  = array();
        } else {

        }

        $_SESSION['plugin'][$plugin_id]["start_date"] = $_GET["start_date"];
        $_SESSION['plugin'][$plugin_id]["start_time"] = $_GET["start_time"];
        $_SESSION['plugin'][$plugin_id]["end_date"] = $_GET["end_date"];
        $_SESSION['plugin'][$plugin_id]["end_time"] = $_GET["end_time"];
        $_SESSION['plugin'][$plugin_id]["end_time"] = $_GET["end_time"];
        $_SESSION['plugin'][$plugin_id]["attack"] = $_GET["attack"];
	
        $_SESSION['plugin'][$plugin_id]['sources']  = array();
        foreach ($_SESSION['profileinfo']["channel"] as $channel) {
                if ($_GET[$channel["name"]] == "on") {
	                array_push($_SESSION['plugin'][$plugin_id]['sources'], $channel["name"]);
		}
        }
}

/*
 * This function is called after the header and the navigation bar have
 * are sent to the browser. It's now up to this function what to display.
 * This function is called only, if this plugin is selected in the plugins tab
 * Its return value is ignored.
 */
function gabriel_Run( $plugin_id ) {
//        print "<h3>Hello from Gabriel ($plugin_id)</h3>";
        if ($_GET["submitted"] == "true"){ // search data is available in $_GET
                update_session_variables($plugin_id);
        } else {
                // just page refressh
        }
        draw_search($plugin_id)
?>
        <TABLE BORDER=0>
                <TR BGCOLOR="#87D3D3">
                <TD> source </TD>
                <TD> timeslot </TD>
                <TD> attack </TD>                
                <TD> total bytes </TD>
                <TD> total packets </TD>
                <TD> popular packet count </TD>
                <TD> popular packet size </TD>
                <TD> popular packet percentage </TD>
                </TR>

<?php

        // the command to be executed in the backend plugin
        $command = 'gabriel::getdata';

        $last_id = Null;
        for ($i = 1; $i <= 288; $i++) {
                $opts = array();
                $opts['index'] = $i;
                $opts['start_date'] = $_SESSION['plugin'][$plugin_id]["start_date"];
                $opts['start_time'] = $_SESSION['plugin'][$plugin_id]["start_time"];
                $opts['end_date'] = $_SESSION['plugin'][$plugin_id]["end_date"];
                $opts['end_time'] = $_SESSION['plugin'][$plugin_id]["end_time"];
                $opts['attack'] = $_SESSION['plugin'][$plugin_id]["attack"] == "on" ? 1 : 0;

                $opts['n_sources'] = count($_SESSION['plugin'][$plugin_id]['sources']);
                for ($j = 0; $j < count($_SESSION['plugin'][$plugin_id]['sources']); $j++) {
                        $opts['source_' . $j] = $_SESSION['plugin'][$plugin_id]['sources'][$j];
                }
                

                $out_list = nfsend_query($command, $opts);
                if ( !is_array($out_list) ) {
                        SetMessage('error', "Error calling backend plugin");
                        ShowMessages();
                        return FALSE;
                }

                $source = $out_list['source'];
                $timeslot = $out_list['timeslot'];
                $id = $out_list['id'];
                if ($id == $last_id) break;
                $last_id = $id;
                $attack = $out_list['attack'];
                $total_bytes = $out_list['total_bytes'];
                $popular_packet_count = $out_list['popular_packet_count'];
                $total_packets = $out_list['total_packets'];
                $popular_packet_size = $out_list['popular_packet_size'];
                $percentage = $out_list['popular_packet_percentage'];
                $color = "#DEE9E9";
                if ($attack == 1) {
                        $color = "#F34000";
                }
                $total_bytes = number_format($total_bytes);
                $total_packets = number_format($total_packets);
                $popular_packet_count = number_format($popular_packet_count);
                $popular_packet_size = number_format($popular_packet_size);
?>
		<TR BGCOLOR="<?=$color?>">
                 <TD><?=$source?></TD>
                 <TD><?=$timeslot?></TD>
                 <TD><?=$attack?></TD>
                 <TD><?=$total_bytes?></TD>
                 <TD><?=$total_packets?></TD>
                 <TD><?=$popular_packet_count?></TD>
                 <TD><?=$popular_packet_size?></TD>
                 <TD><?=$percentage?></TD>
		</TR>
<?php
        }
?>
        </TABLE>
<?php
}

?>
