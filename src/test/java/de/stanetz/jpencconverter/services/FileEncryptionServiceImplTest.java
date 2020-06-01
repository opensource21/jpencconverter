package de.stanetz.jpencconverter.services;

import de.stanetz.jpencconverter.cryption.JavaPasswordbasedCryption;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.*;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@TestMethodOrder(MethodOrderer.Alphanumeric.class)
class FileEncryptionServiceImplTest {

    private static final String TEST_ENCRYPTED = "./log/test/encrypted";
    private static final String TEST_DECRYPTED = "./log/test/decrypted";
    private static final String FIRST_LINE = "Hello this is a testfile.";
    private static final String SECOND_LINE = "\u00e4\u00f6\u00fc\u00dfqwe\u20acdahfla fa lfha fh ajdfh ajhf ahf ajhf lhdslahfsajlhfalh adjhf ahf lahlfhasdl\u05D0\ua707\u4e16\u754c\u60a8\u597d";

    private final FileEncryptionService testee = new FileEncryptionServiceImpl();
    private final char[] password = "geheim".toCharArray();
    private final Logger spyLogger = spy(LogManager.getLogger("de.stanetz.spy"));

    @BeforeEach
    public void prepare() throws IOException {
        ReflectionTestUtils.setField(testee, "depth", 4);
        ReflectionTestUtils.setField(testee, "encryptedDir", TEST_ENCRYPTED);
        ReflectionTestUtils.setField(testee, "decryptedDir", TEST_DECRYPTED);
        ReflectionTestUtils.setField(testee, "plainTextExtensions", Arrays.asList("md", "markdown"));
        ReflectionTestUtils.setField(testee, "encryptExtension", ".jenc");
        ReflectionTestUtils.setField(testee, "logger", spyLogger);
        Files.createDirectories(Paths.get(TEST_DECRYPTED));
        Files.createDirectories(Paths.get(TEST_ENCRYPTED));
    }

    @AfterEach
    public void checkLog() {
        verify(spyLogger, never()).error(anyString(), any(Throwable.class));
    }

    @Test
    void test1encryptTextFilesInPath() throws IOException {
        final Path neededInNextTest1 = createFile("Test1.md");
        final Path neededInNextTest2 = createFile("Test2.md");
        testee.encryptTextFilesInPath(password);
        assertThat(getEncryptedPath(neededInNextTest1)).exists();
        assertThat(getEncryptedPath(neededInNextTest2)).exists();
    }

    @Test
    void test2decryptOldTextFileInPath() throws IOException {
        final Path file1 = Paths.get(TEST_DECRYPTED, "dir1", "Test1.md");
        final Path file2 = Paths.get(TEST_DECRYPTED, "dir1", "Test2.md");
        try {
            testee.decryptTextFilesInPath(password);
            assertThat(file1).exists();
            assertThat(file2).exists();
        } finally {
            deleteFiles(file1);
            deleteFiles(file2);
        }
    }

    @Test
    void test3decrypt2TextFilesInPath() throws IOException {
        final Path file1 = createEncryptedFile("Test3.md");
        final Path file2 = createEncryptedFile("Test4.md");
        final Path encryptedPath1 = getEncryptedPath(file1);
        final Path encryptedPath2 = getEncryptedPath(file2);
        try {
            testee.decryptTextFilesInPath(password);
            assertThat(encryptedPath1).exists();
            assertThat(encryptedPath2).exists();
        } finally {
            deleteFiles(file1);
            deleteFiles(file2);
        }
    }


    @Test
    void test6Roundtrip() throws IOException {
        final Path file1 = createFile("Test7.md");
        final Path file2 = createFile("Test8.md");
        try {
            testee.encryptTextFilesInPath(password);
            Files.delete(file1);
            Files.delete(file2);
            testee.decryptTextFilesInPath(password);
            assertThat(file1).exists();
            assertThat(file2).exists();
            assertThat(getEncryptedPath(file1)).exists();
            assertThat(getEncryptedPath(file2)).exists();
        } finally {
            deleteFiles(file1);
            deleteFiles(file2);
        }
    }

    private Path createFile(String name) throws IOException {
        final Path path = Paths.get(TEST_DECRYPTED, "dir1", name);
        Files.createDirectories(path.getParent());
        Files.write(path, Arrays.asList(FIRST_LINE, SECOND_LINE));
        return path;
    }

    private Path createEncryptedFile(String name) throws IOException {
        final Path result = Paths.get(TEST_DECRYPTED, "dir2", name);
        Files.createDirectories(result.getParent());
        final Path path = getEncryptedPath(result);
        final JavaPasswordbasedCryption javaPasswordbasedCryption = new JavaPasswordbasedCryption(JavaPasswordbasedCryption.Version.V001, new SecureRandom());
        final byte[] encrypt = javaPasswordbasedCryption.encrypt(String.join(System.lineSeparator(), Arrays.asList(FIRST_LINE, SECOND_LINE)), password.clone());
        Files.write(path, encrypt);
        return result;
    }

    private void deleteFiles(Path file) {
        try {
            Files.deleteIfExists(file);
            Files.deleteIfExists(getEncryptedPath(file));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private Path getEncryptedPath(Path file) {
        return Paths.get(TEST_ENCRYPTED, "dir1", file.getFileName() + ".jenc");
    }

}