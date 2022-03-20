/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/.
 **/

/**
 * Password Backup Tool - Global
 * This file contains functions used by all flavors of Password Backup Tool
 */
var { classes: Cc, interfaces: Ci, utils: Cu } = Components;

Cu.import("resource://gre/modules/Services.jsm");

var CC_loginManager = Cc["@mozilla.org/login-manager;1"];

var passwordExporter = {
    version: '', // Incrementing requires new license acceptance
    linebreak: null,
    accepted: false, // whether user has accepted this version's license
    initiated: false, // whether Password Exporter has been initiated yet

    export: null, // export functions specific to this app version
    import: null, // import functions specific to this app version

    // Called on load and on privacy pref tab load to create the tab overlay because the <tabs> we need doesn't have an ID
    init: function() {
        this.version = passwordExporterLoginMgr.version;

        this.linebreak = this.getLinebreak();

        // Include import/export functions
        this.export = passwordExporterLoginMgr.export;
        this.import = passwordExporterLoginMgr.import;

        // Create string bundle
        this.stringBundle = Services.strings.createBundle("chrome://pwdbackuptool/locale/passwordexporter.properties");

        this.initiated = true;
    },

    // opens passwordmanager.xul to view passwords.. called from button on pwdexDialog.xul only
    viewPasswords: function() {
      window.opener.open(
        "chrome://passwordmgr/content/passwordManager.xul", "",
        "chrome,resizable,centerscreen,maximize=no");
    },

    // checks to see if user has accepted notice for this version and if not, shows window
    checkAgreement: function() {
        var prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("");

        if (prefs.getPrefType('extensions.pwdbackuptool.agreeVersion') == prefs.PREF_STRING) {
            if (this.version == prefs.getCharPref('extensions.pwdbackuptool.agreeVersion')) {
                this.accepted = true;
                return true;
            }
        }

        prefs = null;

        window.openDialog("chrome://pwdbackuptool/content/firstrunDialog.xul", "","chrome,resizable,centerscreen,close=no,modal");
        return false;
    },

    // write pref showing agreement to notice
    setAgreement: function() {
        var prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("");

        prefs.setCharPref('extensions.pwdbackuptool.agreeVersion', this.version);
        this.accepted = true;
    },

    // returns the linebreak for the system doing the exporting
    getLinebreak: function() {
        if (/win/i.test(navigator.platform))
            return '\r\n';
        else if (/mac/i.test(navigator.platform))
            return '\r';
        else
            return '\n';
    },

    // Disables all buttons during an import/export
    disableAllButtons: function() {
        document.getElementById('pwdex-import-btn').disabled = true;
        document.getElementById('pwdex-export-btn').disabled = true;
        document.getElementById('pwdex-import-never-btn').disabled = true;
        document.getElementById('pwdex-export-never-btn').disabled = true;
        document.getElementById('pwdex-encrypt').disabled = true;
        document.getElementById('pwdex-view-passwords').disabled = true;
        document.getElementById('pwdex-close').disabled = true;
    },

    // Re-enables all buttons
    enableAllButtons: function() {
        document.getElementById('pwdex-import-btn').disabled = false;
        document.getElementById('pwdex-export-btn').disabled = false;
        document.getElementById('pwdex-import-never-btn').disabled = false;
        document.getElementById('pwdex-export-never-btn').disabled = false;
        document.getElementById('pwdex-encrypt').disabled = false;
        document.getElementById('pwdex-view-passwords').disabled = false;
        document.getElementById('pwdex-close').disabled = false;
    },

    // returns current date in YYYY-MM-DD format for default file names
    getDateString: function() {
        var date = new Date();

        return date.getFullYear() + '-' + this.leadingZero(date.getMonth() + 1) + '-' + this.leadingZero(date.getDate());
    },

    // returns a number with leading zero
    leadingZero: function(number) {
        return (number < 10 ? '0' + number : number);
    },

    /**
     * Gets the string from the string bundle.
     * @param aKey the key that identifies the string.
     */
    getString : function(aKey) {
      return this.stringBundle.GetStringFromName(aKey);
    },

    // Show the master password prompt if needed. Adapted from:
    // https://dxr.mozilla.org/mozilla-central/rev/88bebcaca249aeaca9197382e89d35b02be8292e/toolkit/components/passwordmgr/content/passwordManager.js#494
    showMasterPasswordPrompt: function() {
        // This doesn't harm if passwords are not encrypted
        var tokendb = Cc["@mozilla.org/security/pk11tokendb;1"].createInstance(Ci.nsIPK11TokenDB);
        var token = tokendb.getInternalKeyToken();

        // If there is no master password, still give the user a chance to
        // opt-out of displaying passwords
        if (token.checkPassword(""))
            return true;

        // So there's a master password. But since checkPassword didn't
        //  succeed, we're logged out (per nsIPK11Token.idl).
        try {
            // Relogin and ask for the master password.
            // 'true' means always prompt for token password. User will be
            // prompted until clicking 'Cancel' or entering the correct
            // password.
            token.login(true);
        } catch (e) {
            // An exception will be thrown if the user cancels the login prompt
            // dialog. User is also logged out of Software Security Device.
        }

        return token.isLoggedIn();
    }

};

window.addEventListener("load",  function(e) { if (!passwordExporter.initiated) passwordExporter.init(); }, false);
