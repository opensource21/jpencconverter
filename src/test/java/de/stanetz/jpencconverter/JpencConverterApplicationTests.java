package de.stanetz.jpencconverter;

import de.stanetz.jpencconverter.cryption.JavaPasswordbasedCryption;
import de.stanetz.jpencconverter.services.FileEncryptionService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import javax.annotation.Resource;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestMethodOrder(MethodOrderer.Alphanumeric.class)
class JpencConverterApplicationTests {

    private static final String FIRST_LINE = "Hello this is a testfile.";
    private static final String SECOND_LINE = "\u00e4\u00f6\u00fc\u00dfqwe\u20acdahfla fa lfha fh ajdfh ajhf ahf ajhf lhdslahfsajlhfalh adjhf ahf lahlfhasdl\u05D0\ua707\u4e16\u754c\u60a8\u597d";

    @Value("${filesearch.encdir}")
    private String encryptedDir;

    @Value("${filesearch.decdir}")
    private String decryptedDir;

    @Value("${password}")
    private String password;

    @Resource
    private FileEncryptionService fileEncryptionService;

    @AfterEach
    public void cleanup() throws IOException {
        Files.deleteIfExists(Paths.get(decryptedDir, "Test3.md"));
        Files.deleteIfExists(Paths.get(encryptedDir, "Test4.md.jenc"));
    }

    @Test
    void test1Encryption() throws Exception {
        final Path encryptedFile = Paths.get(encryptedDir, "Test1.md.jenc");
        final Path encryptedFile2 = Paths.get(encryptedDir, "Test2.md.jenc");
        final Path decryptedFile = Paths.get(decryptedDir, "Test1.md");
        try {
            final List<String> plainText = Files.readAllLines(decryptedFile);
            assertThat(plainText).containsExactly(FIRST_LINE, SECOND_LINE);
            final List<String> decryptText = decryptText(encryptedFile);
            assertThat(decryptText).containsExactly(FIRST_LINE, SECOND_LINE);
            Files.copy(encryptedFile, encryptedFile2);
        } finally {
            Files.deleteIfExists(encryptedFile);

        }
    }

    @Test
    void test2Decryption() throws Exception {
        final Path encryptedFile = Paths.get(encryptedDir, "Test2.md.jenc");
        final Path decryptedFile = Paths.get(decryptedDir, "Test2.md");
        try {
            fileEncryptionService.decryptTextFilesInPath(password.toCharArray());
            final List<String> decryptText = decryptText(encryptedFile);
            assertThat(decryptText).containsExactly(FIRST_LINE, SECOND_LINE);
            final List<String> plainText = Files.readAllLines(decryptedFile);
            assertThat(plainText).containsExactly(FIRST_LINE, SECOND_LINE);
        } finally {
            Files.deleteIfExists(encryptedFile);
            Files.deleteIfExists(decryptedFile);
        }
    }

    private List<String> decryptText(Path file) throws IOException, JavaPasswordbasedCryption.EncryptionFailedException {
        final byte[] encryptedBytes = Files.readAllBytes(file);
        final String decrypt = JavaPasswordbasedCryption.getDecyptedText(encryptedBytes, password.toCharArray());

        return Arrays.asList(decrypt.split("[\\r\\n]+"));
    }

}
