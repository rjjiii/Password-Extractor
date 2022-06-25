/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/.
 **/

"use strict";










//
// XUL-based extensions put their code into standard JavaScript files.
// Refer to Mozilla's documentation for K-Meleon's engine's API.
// Refer to the K-Meleon wiki for K-Meleon interface APIs.
//
// K-Meleon specific features are handled by the jsBridge Kplugin.
//
//
// This extension will create a button on the toolbar and a menu item.
// Default toolbar: "Browser Con&figuration" (this is fine for most extensions)
// Menu: CloseWindow (choose a section that matches your extension)
// 
// 
// Create a "hello_world@extensions.kmeleonbrowser.org" string preference (in 
// about:config page) to override defaults.
// Simple KM macros can also change preferences to interact with xpi extensions.
//

var prefBranch = 'hello_world@extensions.kmeleonbrowser.org.'
var ToolbarDefault = 'Browser Con&figuration';
var MenuDefault = '&Tools';


var Toolbar = '';
var CmdName = 'Password Extractor';

var jsb = null;

//===========================================//

Components.utils.import("resource://gre/modules/Services.jsm");

var timer = Components.classes["@mozilla.org/timer;1"]
             .createInstance(Components.interfaces.nsITimer); 

var active = false;


//===========================================//


//===========================================//
function startup(aData, aReason) {

  if(active) { return };
  active = true;

  delayed_startup();

};

//===========================================//

function delayed_startup() { 

  // trying to get the JSBridge pointer
  //  and wait for the JSBridge to be ready (occurs when the browser starts)
  jsb = null;
  try {
    jsb = Components.classes["@kmeleon/jsbridge;1"].getService(Components.interfaces.nsIJSBridge);
  } catch(e) { };

  if(jsb==null) {
    timer.initWithCallback(delayed_startup, 300, Components.interfaces.nsITimer.TYPE_ONE_SHOT);
    return;
  };


  // get prefs
  // getPrefType : PREF_INVALID, PREF_STRING, PREF_INT, PREF_BOOL 
  // getCharPref, getIntPref, getBoolPref, getPrefType, resetBranch('')
  var prefs = Components.classes["@mozilla.org/preferences-service;1"]
              .getService(Components.interfaces.nsIPrefService).getBranch(prefBranch);
  Toolbar = (prefs.getPrefType("toolbar") == prefs.PREF_STRING) ?
     prefs.getCharPref("toolbar") : ToolbarDefault;


//syntax: jsb.SetMenuCallback("menu", "label", fucntion(){}, location);
jsb.SetMenuCallback(MenuDefault, CmdName, function(wind, mode, arg) {
	              
    let watcher = Components.classes["@mozilla.org/embedcomp/window-watcher;1"]
                            .getService(Components.interfaces.nsIWindowWatcher);

    watcher.openWindow(
      null,
      'chrome://pwdextractor/content/pwdexDialog.xul',
      'Password Extractor',
      'chrome,titlebar,toolbar,centerscreen,modal,resizable',
      null
	  );
  }, -1);

};

//===========================================//
 
function shutdown(aData, aReason) {};

//===========================================//

function install(aData, aReason) {}


function uninstall(aData, aReason) {}

//===========================================//

function popupAlert(title, msg) {

  Services.prompt.alert(null, title, msg);
}

//===========================================//