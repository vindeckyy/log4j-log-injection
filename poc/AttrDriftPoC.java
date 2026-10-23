import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Proof of concept for the Log4j 3.x Rfc5424Layout attribute-rename defect.
 *
 * Writes one log event whose message contains an embedded newline. Depending on
 * which Rfc5424Layout attribute the running Log4j version actually honours,
 * that newline is either escaped (one syslog record) or emitted raw (the
 * record is split in two).
 *
 * The message text is the same in every case; only the layout configuration
 * differs.
 */
public final class AttrDriftPoC {

    public static void main(String[] args) throws Exception {
        final Path out = Path.of(System.getProperty("outFile", "out-attrdrift.txt"));
        Files.deleteIfExists(out);

        // A message with an embedded newline. Under RFC 5424 the MSG field must
        // not contain a raw LF unless the record is framed (RFC 5425).
        org.apache.logging.log4j.Logger log =
                org.apache.logging.log4j.LogManager.getLogger("attrdrift");
        log.info("line-one\nline-two");

        // Give the appender a moment to flush, then dump what was written.
        Thread.sleep(300);
        System.out.println("wrote " + out.toAbsolutePath());
        if (Files.exists(out)) {
            byte[] data = Files.readAllBytes(out);
            System.out.println("bytes: " + data.length);
            // Escaping backslashes first makes the output unambiguous: a literal
            // backslash-n shows as \\n, a real newline shows as \n.
            System.out.println("repr : " + new String(data, "UTF-8")
                    .replace("\\", "\\\\")
                    .replace("\r", "\\r")
                    .replace("\n", "\\n"));
        }
    }

    private AttrDriftPoC() {}
}
