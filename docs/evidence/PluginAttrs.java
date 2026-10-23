import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Prints the configuration attribute names a Log4j plugin builder accepts.
 *
 * Log4j binds an XML attribute to a builder field by the field name, or by the
 * name in the field's @PluginBuilderAttribute annotation. This tool lists what
 * a given Log4j version actually accepts, so the accepted spellings can be
 * compared across releases instead of guessed.
 *
 * Usage: java -cp <log4j jars>:. PluginAttrs <fully.qualified.PluginClass>
 */
public final class PluginAttrs {

    public static void main(String[] args) throws Exception {
        final String className = args.length > 0
                ? args[0]
                : "org.apache.logging.log4j.core.layout.Rfc5424Layout";
        final Class<?> plugin = Class.forName(className);

        Class<?> builder = null;
        for (Class<?> c : plugin.getDeclaredClasses()) {
            if (c.getSimpleName().contains("Builder")) {
                builder = c;
                break;
            }
        }
        if (builder == null) {
            System.out.println("no builder class found in " + className);
            return;
        }

        final List<String> names = new ArrayList<>();
        for (Field f : builder.getDeclaredFields()) {
            for (java.lang.annotation.Annotation a : f.getAnnotations()) {
                if (!a.annotationType().getName().endsWith("PluginBuilderAttribute")) {
                    continue;
                }
                String value = null;
                for (Method m : a.annotationType().getDeclaredMethods()) {
                    if ("value".equals(m.getName())) {
                        Object v = m.invoke(a);
                        value = (v instanceof String && !((String) v).isEmpty())
                                ? (String) v : null;
                    }
                }
                names.add(value != null ? value : f.getName());
            }
        }
        Collections.sort(names);

        System.out.println("plugin     : " + className);
        System.out.println("builder    : " + builder.getName());
        System.out.println("attributes : " + names.size());
        for (String n : names) {
            System.out.println("    " + n);
        }
    }

    private PluginAttrs() {}
}
