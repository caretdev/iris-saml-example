FROM intersystemsdc/iris-community

RUN --mount=type=bind,src=.,dst=/home/irisowner/saml-example/ \
  iris start iris && \
  iris session iris '##class(%ZPM.PackageManager).Shell("load /home/irisowner/saml-example/ -v",1,1)' && \
  iris stop iris quietly 