/*
*    Copyright 2014 Cert.gov.ge <cert@dea.gov.ge>
*
*    This file is part of Gabriel.
*
*    Gabriel is free software: you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation, either version 3 of the License, or
*    (at your option) any later version.
*
*    Gabriel is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with Gabriel.  If not, see <http://www.gnu.org/licenses/>.
*    You should have received a copy of the GNU General Public License
*
*/

var pluginName = "gabriel";

function getPluginData() {
    return JSON.parse(localStorage.getItem(pluginName));
}

function storePluginData(pluginData) {
    localStorage.setItem(pluginName, JSON.stringify(pluginData));
}

function values_changed() {
    var pluginData = JSON.parse(localStorage.getItem(pluginName));

    pluginData["start_date"] = document.getElementById("start_date").value;
    pluginData["start_time"] = document.getElementById("start_time").value;
    pluginData["end_date"] = document.getElementById("end_date").value;
    pluginData["end_time"] = document.getElementById("end_time").value;
    pluginData["attack"] = document.getElementById("attack").checked;

    localStorage.setItem(pluginName, JSON.stringify(pluginData));
}

function checkbox_changed(id) {
    var pluginData = getPluginData();

    if (pluginData["sources"] == undefined) {
	pluginData["sources"] = {};
    }
    pluginData["sources"][id] = document.getElementById(id).checked;

    storePluginData(pluginData);
}

function load_values() {
    if (localStorage.getItem(pluginName) == undefined) {
	localStorage.setItem(pluginName, JSON.stringify({}));
    }
    var pluginData = JSON.parse(localStorage.getItem(pluginName));

    if (pluginData["attack"] != undefined) {
      document.getElementById("attack").checked = pluginData["attack"];
    }

    if (pluginData["start_date"] != undefined) {
	document.getElementById("start_date").value = pluginData["start_date"];
    }

    if (pluginData["start_time"] != undefined) {
	document.getElementById("start_time").value = pluginData["start_time"];
    }

    if (pluginData["end_date"] != undefined) {
	document.getElementById("end_date").value = pluginData["end_date"];
    }

    if (pluginData["end_time"] != undefined) {
	document.getElementById("end_time").value = pluginData["end_time"];
    }

    if (pluginData["sources"] != undefined) {
	console.log("sources: ");
	console.log(pluginData["sources"]);
	for (var source in pluginData["sources"]) {
	    document.getElementById(source).checked =
		pluginData["sources"][source];
	}
    }
}



function main() {
    load_values();
}


$('document').ready(function(){
    main();
});
