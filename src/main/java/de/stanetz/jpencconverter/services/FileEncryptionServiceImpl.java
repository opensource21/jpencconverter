package de.stanetz.jpencconverter.services;

import de.stanetz.jpencconverter.cryption.JavaPasswordbasedCryption;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Stream;

@Service
public class FileEncryptionServiceImpl implements FileEncryptionService {

    private static final Random random = new SecureRandom();

    private final Logger logger = LogManager.getLogger(FileEncryptionServiceImpl.class);

    @Value("${filesearch.depth}")
    private int depth;

    @Value("${filesearch.encdir}")
    private String encryptedDir;

    @Value("${filesearch.decdir}")
    private String decryptedDir;

    @Value("${extension.encrypt}")
    private String encryptExtension;

    @Value("#{'${extensions.plainText}'.split(',')}")
    private List<String> plainTextExtensions;

    // This could be interesting in future-versions.
//    @Value("#{'${extensions.plainBin}'.split(',')}")
//    private List<String> plainBinExtensions;

    @Override
    public void encryptTextFilesInPath(char[] password) throws IOException {
        final Path decryptPath = Paths.get(decryptedDir);
        if (Files.notExists(decryptPath)) {
            throw new IllegalStateException(decryptPath.toAbsolutePath().toString() + " doesn't exist");
        }
        logger.debug("Analyze for encrypt {}", decryptPath);
        final Set<String> plainTextExtensionSet = new HashSet<>(plainTextExtensions);
        try (Stream<Path> stream = Files.walk(decryptPath, depth)) {
            stream.filter(file -> !Files.isDirectory(file))
                    .filter(file -> plainTextExtensionSet.contains(getExtension(file.getFileName().toString())))
                    .forEach(it -> {
                        try {
                            logger.debug("Encrypt Text of {}", it);
                            encryptText(password, it);
                        } catch (IOException | JavaPasswordbasedCryption.EncryptionFailedException e) {
                            logger.error("Can't encrypt " + it, e);
                        }
                    });
        }
    }

    private void encryptText(char[] password, Path oldFile) throws IOException, JavaPasswordbasedCryption.EncryptionFailedException {
        final Path newFile = Paths.get(oldFile.toString().replace(decryptedDir, encryptedDir) + encryptExtension);
        final FileTime lastModifiedTimeOldFile = Files.getLastModifiedTime(oldFile);
        if (Files.notExists(newFile) || Files.getLastModifiedTime(newFile).compareTo(lastModifiedTimeOldFile) < 0) {
            final byte[] encrypt = new JavaPasswordbasedCryption(JavaPasswordbasedCryption.Version.V001, random)
                    .encrypt(String.join(System.lineSeparator(), Files.readAllLines(oldFile)), password.clone());
            Files.write(newFile, encrypt);
            Files.setLastModifiedTime(newFile, lastModifiedTimeOldFile);
        } else if (Files.getLastModifiedTime(newFile).compareTo(lastModifiedTimeOldFile) == 0) {
            logger.info("{} has same modification time than {} and will not be encrypt.", newFile, oldFile);
        } else {
            logger.warn("{} is newer than {} and will not be encrypt.", newFile, oldFile);
        }
    }

    @Override
    public void decryptTextFilesInPath(char[] password) throws IOException {
        final Set<String> plainTextExtensionSet = new HashSet<>(plainTextExtensions);
        final Path encryptPath = Paths.get(encryptedDir);
        if (Files.notExists(encryptPath)) {
            throw new IllegalStateException(encryptPath.toAbsolutePath().toString() + " doesn't exist");
        }
        logger.debug("Analyze for decrypt {}.", encryptPath);
        try (Stream<Path> stream = Files.walk(encryptPath, depth)) {
            stream.filter(file -> !Files.isDirectory(file))
                    .filter(file -> file.toString().endsWith(encryptExtension))
                    .filter(file -> {
                        final String filename = file.getFileName().toString();
                        return plainTextExtensionSet.contains(getExtension(filename.substring(0, filename.length() - encryptExtension.length())));
                    })
                    .forEach(it -> {
                        try {
                            logger.debug("Decrypt Text of {}", it);
                            decryptText(password, it);
                        } catch (IOException | JavaPasswordbasedCryption.EncryptionFailedException e) {
                            logger.error("Can't decrypt " + it, e);
                        }
                    });
        }
    }


    private void decryptText(char[] password, Path oldFile) throws
            IOException, JavaPasswordbasedCryption.EncryptionFailedException {
        final String newFilenameWithEncExtension = oldFile.toString().replace(encryptedDir, decryptedDir);
        final Path newFile = Paths.get(newFilenameWithEncExtension.substring(0, newFilenameWithEncExtension.length() - encryptExtension.length()));
        final FileTime lastModifiedTimeOldFile = Files.getLastModifiedTime(oldFile);
        if (Files.notExists(newFile) || Files.getLastModifiedTime(newFile).compareTo(lastModifiedTimeOldFile) < 0) {
            final byte[] encryptedBytes = Files.readAllBytes(oldFile);
            final String decrypt = JavaPasswordbasedCryption.getDecyptedText(encryptedBytes, password.clone());
            final List<String> lines = Arrays.asList(decrypt.split("[\\r\\n]+"));
            Files.write(newFile, lines, StandardCharsets.UTF_8);
            Files.setLastModifiedTime(newFile, lastModifiedTimeOldFile);
        } else if (Files.getLastModifiedTime(newFile).compareTo(lastModifiedTimeOldFile) == 0) {
            logger.info("{} has same modification time than {} and will not be decrypted.", newFile, oldFile);
        } else {
            logger.warn("{} is newer than {} and will not be decrypted.", newFile, oldFile);
        }
    }

    private String getExtension(String fileName) {
        String extension = "";
        final int i = fileName.lastIndexOf('.');
        if (i > 0) {
            extension = fileName.substring(i + 1);
        }
        return extension;
    }
}
