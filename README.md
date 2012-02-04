<html>
    <head>
    </head>

    <body>
        <center><h1>dnsblcheck</h1></center>
        <p>
        This module provides for DNSBL checking.
        </p>
        <h2>Summary</h2>
        <p>
        DNSBLCheck allows you to set one or more dnsbl servers to check incoming requests. It can be set to 
        make a configuration for per-directory basis and to limit dnsbl queries to specified methods 
        (ex. POST requests).
        </p>
        <h2>Directives</h2>
        <ul>
            <li><a href="#DNSBLCheck">DNSBLCheck</li>
            <li><a href="#DNSBLHosts">DNSBLHosts</li>
            <li><a href="#DNSBLEnv">DNSBLEnv</li>
            <li><a href="#DNSBLAction">DNSBLAction</li>
            <li><a href="#DNSBLLog">DNSBLLog</li>
            <li><a href="#DNSBLMessage">DNSBLMessage</li>
            <li><a href="#DNSBLMethods">DNSBLMethods</li>
            <li><a href="#DNSBLWhitelist">DNSBLWhitelist</li>
        </ul>
        <hr />
        <h2><a id="DNSBLCheck">DNSBLCheck</a></h2>
        <strong>Syntax:</strong> DNSBLCheck On|Off<br/>
        <strong>Default Value:</strong> Off<br />
        <strong>Versions:</strong> 0.1<br />
        <br />
        Set DNSBLCheck to 'On' to use DNSBL for this context.
        <hr />
        <h2><a id="DNSBLHosts">DNSBLHosts</a></h2>
        <strong>Syntax:</strong> DNSBLHosts dnsblserver ..<br/>
        <strong>Default Value:</strong> None<br />
        <strong>Versions:</strong> 0.1<br />
        <strong>Example:</strong> DNSBLHosts dnsbl1.yourdnsbl.domain dnsbl2.yourdnsbl.domain<br />
        <br />
        Set DNS suffix for lookup.<br />
        Note: If a IP source address is match for example on dnsbl1.yourdnsbl.domain the other dnsbl hosts will
        not be checked in order to improve performance.
        <hr />
        <h2><a id="DNSBLEnv">DNSBLEnv</a></h2>
        <strong>Syntax:</strong> DNSBLEnv On|Off<br/>
        <strong>Default Value:</strong> On<br />
        <strong>Versions:</strong> 0.1<br />
        <br />
        Set the following environment variables:<br /><br />
        DNSBL_CHECK -> 1<br /> 
        DNSBL_HOST -> dnsbl suffix (according to <a href="#DNSBLHosts">DNSBLHosts</a>) positive to this request<br />
        <br /> 
        These variables are set only if <a href="#DNSBLActions">DNSBLAction</a> is not 'Block'
        <hr />
        <h2><a id="DNSBLAction">DNSBLAction</a></h2>
        <strong>Syntax:</strong> DNSBLAction Block|Test<br/>
        <strong>Default Value:</strong> Test<br />
        <strong>Versions:</strong> 0.1<br />
        <br />
        Action to perform for this context if the source ip address is listed on <a href="#DNSBLHosts">DNSBLHosts</a>
        <hr />
        <h2><a id="DNSBLLog">DNSBLLog</a></h2>
        <strong>Syntax:</strong> DNSBLLog On|Off<br/>
        <strong>Default Value:</strong> On<br />
        <strong>Versions:</strong> 0.1<br />
        <br />
        Log requests when matched by <a href="#DNSBLHosts">DNSBLHosts<a>.
        <hr />
        <h2><a id="DNSBLMessage">DNSBLMessage</a></h2>
        <strong>Syntax:</strong> DNSBLMessage message<br/>
        <strong>Default Value:</strong> "Blocked for SPAM"<br />
        <strong>Versions:</strong> 0.1<br />
        <strong>Example:</strong> DNSBLMessage "Blocked for SPAM"<br />
        <br />
        Message to show for blocked requests.<br />
        Note: Message is set with Content Type to plain/text and with Forbidden status. 
        <hr />
        <h2><a id="DNSBLMethods">DNSBLMethods</a></h2>
        <strong>Syntax:</strong> DNSBLMethods method1 ...<br/>
        <strong>Default Value:</strong> all<br />
        <strong>Versions:</strong> 0.1<br />
        <strong>Example:</strong> DNSBLMethods: POST PUT DELETE<br />
        <br />
        Limit dnsbl checking to these request methods.
        <hr />
        <h2><a id="DNSBLWhitelist">DNSBLWhitelist</a></h2>
        <strong>Syntax:</strong> DNSBLWhitelist ipaddress|domainname|ipaddr/netmask|env=var ...<br/>
        <strong>Default Value:</strong> all<br />
        <strong>Versions:</strong> 0.1<br />
        <strong>Example:</strong> DNSBLWhitelist: dancingbear.it 10.0.1.0/24 10.0.1.0/255.255.255.0 env=myrobot<br />
        <br />
        Whitelist directive with syntax very similiar to mod_access.

        For example you can give:

        <code><pre>
        SetEnvIf User-Agent ^Edy/2\.0 edy

        &ltDirectory /docroot&gt
            DNSBLCheck on
            DNSBLHosts dnsbl1.abc.cde
            DNSBLWhiteList env=edy
        &lt/Directory&gt
        </pre></code>
<hr />         
<h2>Examples</h2>
Per-Directory configuration:
<br />
cat /etc/apache2/mods-enabled/dnsblcheck.conf
<br />
<code><pre>
&ltIfModule dnsblcheck.c&gt
    DNSBLHosts dnsbl1.domain
    DNSBLWhitelist 10.0.1.0/24
    DNSBLMethods POST
    DNSBLMessage "Blocked for SPAM"
    DNSBLCheck off


    &ltDirectory /var/www/domainA&gt
        DNSBLCheck on
    &lt/Directory&gt

    &ltDirectory /var/www/domainB&gt
        DNSBLCheck on
	DNSBLAction block
        DNSBLHosts dnsbl1.domain dnsbl2.domain 
        DNSBLMethods POST PUT DELETE
    &lt/Directory&gt
&lt/IfModule&gt
</pre></code>

    </body>
</html>

