import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Proof of concept for the Log4j 3.x JsonTemplateLayout non-finite number defect.
 *
 * Logs one event whose message carries a Double.NaN. A JSON layout is expected
 * to emit valid JSON; the question is whether the non-finite number is written
 * as a quoted string ("NaN", valid JSON) or as a bare token (NaN, which is not
 * valid JSON at all).
 *
 * The same event, the same template and the same layout are used against every
 * Log4j version under test.
 */
public final class JsonNaNPoC {

    public static void main(String[] args) throws Exception {
        final Path out = Path.of(System.getProperty("outFile", "out-jsonnan.txt"));
        Files.deleteIfExists(out);

        final Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("measurement", Double.NaN);
        payload.put("other", 1.5d);

        org.apache.logging.log4j.Logger log =
                org.apache.logging.log4j.LogManager.getLogger("jsonnan");
        log.info(new org.apache.logging.log4j.message.ObjectMessage(payload));

        Thread.sleep(300);
        System.out.println("wrote " + out.toAbsolutePath());
        if (Files.exists(out)) {
            String data = new String(Files.readAllBytes(out), "UTF-8");
            System.out.println("repr  : " + data.replace("\r", "\\r").replace("\n", "\\n"));
        }
    }

    private JsonNaNPoC() {}
}
