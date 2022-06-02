function FindProxyForURL(url, host) { // variable strings to return // a Caixa desde IBM //
    var proxy_caixa = "PROXY 10.115.4.2:8080"; //
    var proxy_caixa = "PROXY 10.115.4.1:8080"; //
    var proxy_caixa = "PROXY 10.117.20.47:8080"; //
    var proxy_ibm = "DIRECT";
    var proxy_ibm = "PROXY proxy.emea.ibm.com:8080";
    var proxy_no = "DIRECT";
    var proxy_caixa_nexe = "PROXY proxynexe.svb.lacaixa.es:8080"; //Nou Proxy d'accés a Caixa per a proveedors
    var proxy_caixa_10_115 = "PROXY 10.115.4.2:8080";
    var proxy_caixa_10_113 = "PROXY 10.113.10.13:8080"; // Demana login en popup
    var proxy_caixa_10_121 = "PROXY 10.121.33.29:8080";
    var proxy_caixa = proxy_caixa_10_115;
    if (isInNet(host, "192.168.0.0", "255.255.255.0")) {
        return returnProxy(url, host, proxy_no, "A");
    } // Xarxa local
    if (isInNet(host, "192.168.1.0", "255.255.255.0")) {
        return returnProxy(url, host, proxy_no, "B");
    } // Xarxa local
    if (isInNet(host, "10.20.0.0", "255.255.0.0")) {
        return returnProxy(url, host, proxy_no, "C");
    } // Xarxa local
    if (isInNet(host, "10.5.50.0", "255.255.255.0")) {
        return returnProxy(url, host, proxy_no, "C");
    } // Xarxa local
    if (shExpMatch(url, "http*://127.0.0.1*")) {
        return returnProxy(url, host, proxy_no, "D");
    }
    if (shExpMatch(url, "http*://localhost*")) {
        return returnProxy(url, host, proxy_no, "E");
    }
    if (shExpMatch(host, "fedsrv.caixabank.com")) {
        return returnProxy(url, host, proxy_caixa, "J2");
    } // caixatf.q-go.net //
    //if (shExpMatch(url, "https://email.lacaixa.es*")) {
    //    return returnProxy(url, host, proxy_no, "F");
    //} // per al correu OWA podem anar sense proxy
    if (shExpMatch(url, "http*://arwnew.lacaixa.es*")) {
        return returnProxy(url, host, proxy_no, "G");
    } //per activar VPN CBK per a empreses externes
    if (shExpMatch(url, "http*://*sch*.lacaixa.es*")) {
        return returnProxy(url, host, proxy_caixa, "H");
    }
    if (shExpMatch(url, "*.lacaixa.es*")) {
        return returnProxy(url, host, proxy_caixa, "I");
    }
    if (shExpMatch(url, "*.caixabank.com*")) {
        return returnProxy(url, host, proxy_caixa, "I");
    }
    if (shExpMatch(url, "*.lacaixa.glc.es*")) {
        return returnProxy(url, host, proxy_caixa, "J");
    }
    if (shExpMatch(url, "*.q-go.net*")) {
        return returnProxy(url, host, proxy_caixa, "J1");
    } // caixatf.q-go.net
    if (shExpMatch(url, "http*://9.*")) {
        return returnProxy(url, host, proxy_ibm, "K");
    } //
    if (shExpMatch(url, "http*://*ibm.com*")) {
        return returnProxy(url, host, proxy_ibm, "L");
    }
    if (shExpMatch(url, "http*://*insags.com*")) {
        return returnProxy(url, host, proxy_no, "Z");
    } // Whitelist the following wildcards: *.slack.com *.slack-msgs.com *.slack-files.com *.slack-imgs.com *.slack-edge.com *.slack-core.com *.slack-redir.net. // Check if your proxy is running SSL decryption. If it is, the proxy must either support WebSockets, or you’ll need to exempt *.slack-msgs.com from SSL decryption.
    if (shExpMatch(url, "*slack.com*") || shExpMatch(url, "*slack-edge.com*") || shExpMatch(url, "*slack-msgs.com*") || shExpMatch(url, "*slack-files.com*") || shExpMatch(url, "*slack-imgs.com*") || shExpMatch(url, "*slack-core.com*") || shExpMatch(url, "*slack-redir.net*")) {
        return returnProxy(url, host, proxy_no, "a");
    } //
    if (isInNet(host, "172.18.0.0", "255.255.0.0")) {
        return returnProxy(url, host, proxy_caixa, "M");
    } // Jira i Drupal documentació ABSIS
    if (isInNet(host, "172.18.10.0", "255.255.255.0")) {
        return returnProxy(url, host, proxy_no, "Y");
    } // rtc-ext.insags.com [172.18.10.114]
    if (isInNet(host, "172.16.35.0", "255.255.255.0")) {
        return returnProxy(url, host, proxy_no, "N");
    } // Biblio Hospitalet Infant
    if (isInNet(host, "172.18.252.40", "255.255.255.255")) {
        return returnProxy(url, host, proxy_caixa, "O");
    } // Repositori SVN Aplicacions
    if (isInNet(host, "172.18.254.92", "255.255.255.255")) {
        return returnProxy(url, host, proxy_caixa, "P");
    } // Repositori SVN Infrastructures
    if (isInNet(host, "7.0.0.0", "255.0.0.0")) {
        return returnProxy(url, host, proxy_caixa, "Q");
    }
    if (isInNet(host, "10.0.0.0", "255.0.0.0")) {
        return returnProxy(url, host, proxy_caixa, "R");
    } //
    if (isInNet(host, "128.30.0.0", "255.255.0.0")) {
        return returnProxy(url, host, proxy_no, "S");
    } // WWW.W3.ORG //
    if (isInNet(host, "128.112.0.0", "255.255.0.0")) {
        return returnProxy(url, host, proxy_no, "S2");
    } // wordnet-rdf.princeton.edu //
    if (isInNet(host, "128.0.0.0", "255.0.0.0")) {
        return returnProxy(url, host, proxy_caixa, "T");
    } // Perque està redirigit cap a caixa?????
    if (isInNet(host, "172.20.0.0", "255.255.0.0")) {
        return returnProxy(url, host, proxy_caixa, "U");
    } //SCH PRO Centre2 (172.20..), per PROXY-CAIXA-ANTIC, SCH PRO Centre1 (172.18..), NO PROXY
    if (isInNet(host, "172.16.0.0", "255.240.0.0")) {
        return returnProxy(url, host, proxy_no, "V");
    }
    if (isInNet(host, "192.168.0.0", "255.255.0.0")) {
        return returnProxy(url, host, proxy_caixa, "W");
    } //
    if (isInNet(host, "217.16.250.0", "255.255.255.0")) {
        return returnProxy(url, host, proxy_no, "X");
    } //** ENTRADAS SALESFORCE
    if (shExpMatch(url, "*.force.com*")) {
        return returnProxy(url, host, proxy_caixa, "I");
    }
    if (shExpMatch(url, "*.salesforce.com*")) {
        return returnProxy(url, host, proxy_caixa, "I");
    }
    if (shExpMatch(url, "*.documentforce.com*")) {
        return returnProxy(url, host, proxy_caixa, "I");
    }
    if (shExpMatch(url, "*.salesforceliveagent.com*")) {
        return returnProxy(url, host, proxy_caixa, "I");
    }
    if (shExpMatch(url, "*.visualforce.com*")) {
        return returnProxy(url, host, proxy_caixa, "I");
    }
    if (shExpMatch(url, "*.lightning.com*")) {
        return returnProxy(url, host, proxy_caixa, "I");
    }
    if (shExpMatch(url, "*.salesforce-communities.com*")) {
        return returnProxy(url, host, proxy_caixa, "I");
    }
    if (shExpMatch(url, "*.forceusercontent.com*")) {
        return returnProxy(url, host, proxy_caixa, "I");
    }
	if (shExpMatch(url, "*viewnext*") || shExpMatch(url, "*teams.microsoft.com*") || shExpMatch(url, "*statics.teams.cdn.office.net*") || shExpMatch(url, "*.teams.*") || shExpMatch(url, "*microsoft*") || shExpMatch(url, "*slack-core.com*") || shExpMatch(url, "*slack-redir.net*")) {
        return returnProxy(url, host, proxy_no, "a");
    } // Proxy anything else
    return returnProxy(url, host, proxy_no, "Y");
}

function returnProxy(url, host, proxy, point) { // alert("S'ha resolt la url: "+url+" (host:"+host+") amb el proxy "+proxy+" en el punt "+point);
    return proxy;
}
