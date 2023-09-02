package org.wergeland.digipost;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Enumeration;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EncryptAndDecrypt {

    public static void main(final String[] args) throws Exception {
        Options options = new Options();
        options.addOption(Option.builder("k").hasArg().argName("keyfile").build());
        options.addOption(Option.builder("p").hasArg().argName("passphrase").build());
        CommandLine line = new DefaultParser().parse(options, args);

        String[] files = line.getArgs();
        if (files.length < 1 || files.length > 2) {
            System.out.println("Usage: java -jar digipost.jar -k <keyfile> -p <passphrase> infile [outfile]");
            System.exit(1);
        }
        File keyfile = new File(line.getOptionValue("k", "key.p12"));

        File infile = new File(files[0]);
        if (!Files.exists(infile.toPath())) {
            System.out.printf("No such file: %s%n", files[0]);
            System.exit(1);
        }

        File outfile;
        if (files.length == 2) {
            outfile = new File(files[1]);
        } else {
            outfile = new File(files[0].substring(0, files[0].length() - 4));
        }

        if (Files.exists(outfile.toPath())) {
            System.out.printf("Cannot overwrite: %s%n", outfile.getAbsolutePath());
            System.exit(1);
        }

        Security.addProvider(new BouncyCastleProvider());

        PrivateKey privateKey = getPrivateKey(keyfile, line.getOptionValue("p", ""));
        decrypt(privateKey, infile, outfile);
    }

    private static void decrypt(PrivateKey privateKey, File encrypted, File decryptedDestination)
            throws IOException, CMSException {
        byte[] encryptedData = Files.readAllBytes(encrypted.toPath());

        CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(encryptedData);

        RecipientInformation recInfo = parser.getRecipientInfos().getRecipients().iterator().next();
        Recipient recipient = new JceKeyTransEnvelopedRecipient(privateKey);

        try (InputStream decryptedStream = recInfo.getContentStream(recipient).getContentStream()) {
            Files.copy(decryptedStream, decryptedDestination.toPath());
        }
        System.out.printf(
                "Decrypted '%s' to '%s'%n",
                encrypted.getAbsolutePath(),
                decryptedDestination.getAbsolutePath());
    }

    private static PrivateKey getPrivateKey(File file, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(file)) {
            ks.load(fis, password.toCharArray());
        }
        Enumeration<String> aliases = ks.aliases();
        String alias = aliases.nextElement();
        return (PrivateKey) ks.getKey(alias, password.toCharArray());
    }
}