function changeTz() {
	var sel = document.getElementById("select_tz").value;
	document.getElementById("txt_timezone").value = sel;
}

function writeLocaleNumber(num) {
	document.write(num.toLocaleString());
}

function selectListValue(selectName, currentValue) {
	var mySelect = document.getElementById(selectName);
	var opts = mySelect.options;
	
	for (var opt, j = 0; opt = opts[j]; j++) {
		if (opt.value == currentValue) {
			mySelect.selectedIndex = j;
			break;
		}
	}
}

selectListValue("select_printer_enabled", current_printer_enabled);
selectListValue("select_modem_enabled", current_modem_enabled);
selectListValue("select_modem_sniffer_enabled", current_modem_sniffer_enabled);
selectListValue("select_printermodel1", current_printer);
selectListValue("select_printerport1", current_printerport);
selectListValue("select_hsioindex", current_hsioindex);
selectListValue("select_rotation_sounds", current_rotation_sounds);
selectListValue("select_config_enable", current_config_enabled);
selectListValue("select_boot_mode", current_boot_mode);
selectListValue("select_play_record", current_play_record);
selectListValue("select_pulldown", current_pulldown);
selectListValue("select_cassette_enabled", current_cassette_enabled);
selectListValue("select_status_wait_enable", current_status_wait_enabled);
