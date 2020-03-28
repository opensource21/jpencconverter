package de.stanetz.jpencconverter.controller;

import de.stanetz.jpencconverter.services.FileEncryptionService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Scanner;

@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
@Component
public class CommandlineController implements CommandLineRunner {

    private static final Logger logger = LogManager.getLogger(CommandlineController.class);

    private final Optional<String> storedPassword;

    private final FileEncryptionService fileEncryptionService;

    @Autowired
    public CommandlineController(@Value("${password:#{null}}") Optional<String> storedPassword, FileEncryptionService fileEncryptionService) {
        this.storedPassword = storedPassword;
        this.fileEncryptionService = fileEncryptionService;
    }

    @Override
    public void run(String... args) throws Exception {
        final Mode mode;
        if (args.length == 0 || "sync".equalsIgnoreCase(args[0])) {
            mode = Mode.SYNC;
        } else if ("sync_daemon".equalsIgnoreCase(args[0])) {
            mode = Mode.SYNC_DAEMON;
        } else if ("encrypt".equalsIgnoreCase(args[0])) {
            mode = Mode.ENCRYPT;
        } else if ("decrypt".equalsIgnoreCase(args[0])) {
            mode = Mode.DECRYPT;
        } else {
            throw new IllegalArgumentException("First argument must be sync, encrypt or decrypt");
        }
        logger.info("Running mode {}.", mode);

        final char[] password;
        if (storedPassword.isPresent()) {
            password = storedPassword.get().toCharArray();
        } else {
            System.out.println("Enter password:");
            final Scanner scan = new Scanner(System.in);
            password = scan.nextLine().toCharArray();
        }

        boolean second = false;
        //noinspection LoopConditionNotUpdatedInsideLoop
        do {
            switch (mode) {
                case SYNC_DAEMON:
                    if (second) {
                        Thread.sleep(30000);
                    } else {
                        second = true;
                    }
                case SYNC:
                    fileEncryptionService.decryptTextFilesInPath(password);
                    fileEncryptionService.encryptTextFilesInPath(password);
                    break;
                case DECRYPT:
                    fileEncryptionService.decryptTextFilesInPath(password);
                    break;
                case ENCRYPT:
                    fileEncryptionService.encryptTextFilesInPath(password);
                    break;
            }
        } while (mode == Mode.SYNC_DAEMON);
    }

    public enum Mode {
        ENCRYPT, DECRYPT, SYNC_DAEMON, SYNC
    }
}


