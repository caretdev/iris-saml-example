Include (%occSAX, %soap)

Class caretdev.examples.saml.MyApp Extends %CSP.Page
{

Parameter SettingsGN = "^SAMLSettings";

ClassMethod OnPage() As %Status
{
  &html<<!doctype html>
  <html><body style="padding: 20px;">>
  Write $Username
  Set instanceId = ##class(%SYS.System).InstanceGUID()
  Set spEntityId = "https://intersystems.com/saml/"_instanceId
  &html<<h1>SAML Authentication Example</h1>
  <form enctype="multipart/form-data" method='POST'>
  <p>Use these settings to configure Identity Provider</p>
  <div><b>Login URL, ACS Url:</b> <input type="text" id="acsUrl" name="acsUrl" size="100" /></div>
  <div><b>EntityId:</b> <i>#(spEntityId)#</i></div>
  <br/>
  <div><b>Identity provider Metadata file:</b> <input type="file" name="metadata"/></div>
  <div><input type="submit" /></div>
  <div><input type="submit" name="clear" value="Clear" /></div>
  </form>
  >

  Set samlResponse = %request.Get("SAMLResponse")
  If (samlResponse'="") {
    Set tSAML = $System.Encryption.Base64Decode(samlResponse)
    
    &html<<h3>SAMLResponse</h3>
    <pre style="white-space: pre-wrap;">#($ZConvert(tSAML, "O", "HTML"))#</pre>>

    #; t—Must contain an Authorization header SAML token with key 'access_token='
    #; a—Token must contain an Assertion.
    #; r—Requires Assertions to contain NotBefore/NotOnOrAfter time conditions
    #; v—Verifies Assertion signatures using a Trusted X.509 certificate and, if present, NotBefore/NotOnOrAfter conditions.
    #; o—Validates other signed nodes such as TimeStamp.
    Set tValSpec = "tarvo"
    Set tClockSkew = 0

    Set X509File = ##class(%Stream.FileCharacter).%New()
    Set X509File.Filename = ##class(%File).TempFilename("cer")
    Do X509File.Write(@..#SettingsGN@("x509"))
    Set tSC = X509File.%Save()

    Set tSC = ##class(Ens.Util.XML.SecuritySignature).ValidateSAML(tSAML, tValSpec, X509File.Filename, tClockSkew)
    #; Do ##class(%File).Delete(X509File.Filename)
    
    &html<<div><b>Validation: </b>>
    If $$$ISERR(tSC) {
      Write $System.Status.GetErrorText(tSC)
    }
    Else {
      &html<<i>Success</i>>

      Set tSC = ##class(%XML.XPATH.Document).CreateFromString(tSAML, .tSAMLDoc,,,,,"saml "_$$$SAMLns)

      Set nameId = ""
      Set nameIDFormat = $Get(@..#SettingsGN@("nameIDFormat"))
      
      Set tContext = "//saml:Assertion/saml:Subject"
      Set tExpr = "saml:NameID[@Format='"_nameIDFormat_"']/text()"
      Set tSC = tSAMLDoc.EvaluateExpression(tContext, tExpr, .tResults)
      If ($$$ISOK(tSC))&&(tResults.Count()) {
        Set nameId = tResults.GetAt(1).Value
      }
      &html<<div><b>NameID: </b><i>#(nameId)#</i>>
    }

  }
  ElseIf (%request.IsDefined("clear")) {
    Kill @..#SettingsGN
  }
  ElseIf (%request.IsDefinedMimeData("metadata")) {
    Set metadata = %request.GetMimeData("metadata")
    Set tSC = ..LoadMetadata(metadata)
    Set @..#SettingsGN@("acsUrl") = %request.Get("acsUrl")
  }

  If ($Data(@..#SettingsGN@("ssoUrl"))) {
    Set acsUrl = $Get(@..#SettingsGN@("acsUrl"))
    Set x509 = $Get(@..#SettingsGN@("x509"))
    Set ssoUrl = $Get(@..#SettingsGN@("ssoUrl"))
    Set entityID = $Get(@..#SettingsGN@("entityID"))
    Set nameIDFormat = $Get(@..#SettingsGN@("nameIDFormat"))
    
    Set samlRequest = ..ConstructRequest()
    Set samlRequestXML = $System.Encryption.Base64Decode(samlRequest)

    &html<
    <h2>Identity provider</h2>
    <div><b>ACS Url:</b> <i>#(acsUrl)#</i>
    <div><b>SSO Url:</b> <i>#(ssoUrl)#</i>
    <div><b>Entity Id:</b> <i>#(entityID)#</i>
    <div><b>nameIDFormat:</b> <i>#(nameIDFormat)#</i>
    <div><b>Certificate:</b> <i><pre>#(x509)#</pre></i>
    <div>
    <br/>
    <h3>SAMLRequest</h3>
    <pre style="white-space: pre-wrap;">#($ZConvert(samlRequestXML, "O", "HTML"))#</pre>
    <form method="POST" action="#(ssoUrl)#">
    <input type="hidden" name="SAMLRequest" value="#(samlRequest)#" />
    <input type="submit" value="Login" />
    </form>
    </div>
    >
  }
  
  &html<
  <script>
document.getElementById("acsUrl").value = document.location.href
  </script>>

  &html<<body></html>>  
  Quit $$$OK
}

ClassMethod LoadMetadata(pStream As %Stream) As %Status
{
  Set schemas = $Listbuild(
    "md urn:oasis:names:tc:SAML:2.0:metadata",
    "ds http://www.w3.org/2000/09/xmldsig#"
  )
  $$$QuitOnError(##class(%XML.XPATH.Document).CreateFromStream(pStream, .tDoc, , ,,,$Listtostring(schemas)))

  $$$QuitOnError(tDoc.EvaluateExpression("/md:EntityDescriptor","@entityID", .tRes))
  If (tRes.Size) {
    Set entityID = tRes.GetAt(1).Value
  }
  
  Set tPath = "/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate"
  $$$QuitOnError(tDoc.EvaluateExpression(tPath,"text()", .tRes))
  If (tRes.Size) {
    Set x509 = "-----BEGIN CERTIFICATE-----"_$Char(10)
    Set x509 = x509 _ tRes.GetAt(1).Value_$Char(10)
    Set x509 = x509 _ "-----END CERTIFICATE-----"
  }

  For type="Redirect","POST" {
    Set tPath = "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-"_type_"']"
    Set tSC = tDoc.EvaluateExpression(tPath,"@Location", .tRes)
    Continue:$$$ISERR(tSC)
    Continue:'tRes.Size
    Set ssoUrl = tRes.GetAt(1).Value
    Quit 
  }

  Set tPath = "/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat"
  $$$QuitOnError(tDoc.EvaluateExpression(tPath,"text()", .tRes))
  If (tRes.Size) {
    Set nameIDFormat = tRes.GetAt(1).Value
  }  

  Set @..#SettingsGN@("x509") = x509
  Set @..#SettingsGN@("entityID") = entityID
  Set @..#SettingsGN@("nameIDFormat") = nameIDFormat
  Set @..#SettingsGN@("ssoUrl") = ssoUrl

  Quit $$$OK
}

ClassMethod ConstructRequest(acsUrl As %String) As %String
{
  Set instanceId = ##class(%SYS.System).InstanceGUID()
  Set spEntityId = "https://intersystems.com/saml/"_instanceId

  #define SAMLpns "urn:oasis:names:tc:SAML:2.0:protocol"
  Set ACSURL = $Get(@..#SettingsGN@("acsUrl"))

  #; SP EntityID
  Set issuer = spEntityId
  
  Set destination = $Get(@..#SettingsGN@("ssoUrl"))

  Set timeStamp = $ZDatetime($ZTimestamp, 3, 7)
  Set requestID = "_"_$ZConvert($ZStrip($System.Util.CreateGUID(), "*WCP"), "l")

  Set tXML = ##class(%XML.Writer).%New()
  Do tXML.OutputToString()
  Set tXML.Charset = "UTF-8"
  Set tXML.NoXMLDeclaration = 0
  Set tXML.Indent = 1
  Set tXML.SuppressXmlns = 1
  
  Do tXML.AddNamespace($$$SAMLpns, "samlp")
  Do tXML.AddNamespace($$$SAMLns, "saml")

  Do tXML.RootElement("AuthnRequest", $$$SAMLpns)
  Do tXML.WriteAttribute("ID", requestID)
  Do tXML.WriteAttribute("Version", "2.0")
  Do tXML.WriteAttribute("IssueInstant", timeStamp)
  Do tXML.WriteAttribute("Destination", destination)
  Do tXML.WriteAttribute("AssertionConsumerServiceURL", ACSURL)
  Do tXML.WriteAttribute("IsPassive", "false")

  Do tXML.Element("Issuer", $$$SAMLns)
  Do tXML.Write(issuer)
  Do tXML.EndElement()
  Do tXML.Element("NameIDPolicy", $$$SAMLpns)
  Do tXML.WriteAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
  Do tXML.WriteAttribute("AllowCreate", "false")
  Do tXML.EndElement()

  Do tXML.EndRootElement()

  Set tXMLString = tXML.GetXMLString(.tSC)

  Set tSAMLRequest = $System.Encryption.Base64Encode(tXMLString, 1)

  Quit tSAMLRequest
}

/// Enable Delegated Auth system-wide
/// And add role to CSPSystem, so, it will have access to do delegated auth
ClassMethod ActivateDelegated() As %Status
{
  New $Namespace
  Set namespace = $Namespace
  Set msgGlobal = ##class(%GlobalEdit).Open("IRIS.Msg")
  Set resource = $$$DBDEFAULTResourceName
  If $IsObject(msgGlobal) {
    Set resource = msgGlobal.ResourceName
  }
  Set $Namespace = "%SYS"
  $$$QuitOnError(##class(Security.System).Get(, .p))
  Set p("AutheEnabled") = $ZBoolean(p("AutheEnabled"), $$$AutheDelegated, 7)
  $$$QuitOnError(##class(Security.System).Modify(, .p))
  $$$QuitOnError(##class(Security.Users).AddRoles("CSPSystem", "%DB_IRISLIB"))
  If (resource '= "") {
    $$$QuitOnError(##class(Security.Users).AddRoles("CSPSystem", resource))
  }
  Quit $$$OK
}

}
