# jpencconverter

Passwordbased encryption in java for primary markdown-files. 

Configure application.properties and start with 
`java -jar <jar-file> <mode>`

Mode could be:
- `encrypt` - to encrypt all files
- `decrypt` - to decrypt all files
- `sync` - to de- or encrypt all files
- `sync_daemon` - to sync every 30 seconds.

Look at the `application.properties` for further detail and spring-boot-documention of what could be done.
The properties are described in `src/main/resources/META-INF/additional-spring-configuration-metadata.json`

You can configure logging via log4j2.

The format of the encrypted files is described in [JavaPasswordbasedCryption](https://gitlab.com/opensource21/jpencconverter/-/blob/master/src/main/java/de/stanetz/jpencconverter/cryption/JavaPasswordbasedCryption.java). The format is used in [markor](https://github.com/gsantner/markor).
