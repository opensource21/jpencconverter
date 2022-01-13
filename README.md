# jpencconverter

Passwordbased encryption in java for primary markdown-files.

Download release from [Generic-Repo](https://gitlab.com/opensource21/jpencconverter/-/packages)
for example [0.3.2-Zip](https://gitlab.com/api/v4/projects/17774573/packages/generic/jpencconverter/v0.3.2
/jpenc-converter.zip)

Unzip into a folder jpencconverter (or foo if you prefer this name). I will refer it with basedir.
Rename the `application.properties.sample` to `application.properties` in the basedir.
Edit the `application.properties` following the comments. It's up to you if you want to save the password or insert it at every start.
Go into the folder basedir with a command-shell and start with 
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
