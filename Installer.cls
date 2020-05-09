Class App.Installer
{

XData setup
{
<Manifest>
  <Default Name="SourceDir" Value="#{$System.Process.CurrentDirectory()}src"/>
  <Default Name="Namespace" Value="IRISAPP"/>
  <Default Name="app" Value="irisapp" />

  <Invoke Class="App.Installer" Method="Security" CheckStatus="true" > 
    <Arg Value="%DB_${Namespace}"/>
  </Invoke> 

  <Namespace Name="${Namespace}" Code="${Namespace}-CODE" Data="${Namespace}-DATA" Create="yes" Ensemble="1">

    <Configuration>
      <Database Name="${Namespace}-CODE" Dir="/opt/${app}/code" Create="yes" Resource="%DB_${Namespace}"/>
      <Database Name="${Namespace}-DATA" Dir="/opt/${app}/data" Create="yes" Resource="%DB_${Namespace}"/>
  
      <!-- AuthenticationMethods = Password + Delegated -->
      <CSPApplication 
        Url="/csp/${app}" 
        Directory="${cspdir}${app}" 
        ServeFiles="1" 
        Recurse="1" 
        MatchRoles=":%DB_${Namespace}" 
        AuthenticationMethods="#{$zb(32 /* Password */, 8192 /* Delegated */, 7)}"
        LoginClass="MyApp.cls"
      />
    </Configuration>

    <Import File="${SourceDir}" Flags="ck" Recurse="1"/>
  </Namespace>

  <Invoke Class="App.Installer" Method="SOAPDebug" CheckStatus="true">
    <Arg Value="${Namespace}"/>
    <Arg Value="/opt/${app}/logs"/>
  </Invoke> 


</Manifest>
}

ClassMethod setup(ByRef pVars, pLogLevel As %Integer = 3, pInstaller As %Installer.Installer, pLogger As %Installer.AbstractLogger) As %Status [ CodeMode = objectgenerator, Internal ]
{
  #; Let XGL document generate code for this method. 
  Quit ##class(%Installer.Manifest).%Generate(%compiledclass, %code, "setup")
}

ClassMethod Security(Role) As %Status
{
  New $Namespace
  Set $Namespace = "%SYS"
  $$$QuitOnError(##class(Security.System).Get(, .p))
  Set p("AutheEnabled") = $ZBoolean(p("AutheEnabled"), $$$AutheDelegated, 7)
  $$$QuitOnError(##class(Security.System).Modify(, .p))
  $$$QuitOnError(##class(Security.Users).AddRoles("CSPSystem", Role))
  Quit $$$OK
}

ClassMethod SOAPDebug(Namespace, Path) As %Status
{
  New $Namespace
  Set $Namespace = Namespace
  Set ^ISCSOAP("Log") = "svoit"
  Set ^ISCSOAP("LogFile") = ##class(%File).NormalizeFilename("soap.log", Path)
  Quit $$$OK
}

}
