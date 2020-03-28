package de.stanetz.jpencconverter.services;

import java.io.IOException;

public interface FileEncryptionService {
    void encryptTextFilesInPath(char[] password) throws IOException;

    void decryptTextFilesInPath(char[] password) throws IOException;
}
