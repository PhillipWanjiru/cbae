"""The mutants of src/platform/logging.c: (name, text that occurs exactly once, its replacement). A name starts with its tag.
Used by run_mut.py. The mutants that cannot be told from the original are marked (equivalent) and explained in docs/audit."""
SRC = 'src/platform/logging.c'
TESTS = ['test_logging']

ESCAPE_SEQ = r"""if (is_special(cp)) put_uxxxx(b, cp); else put_raw(b, s + i, seq);"""

SPECIAL = r"""    return (cp >= 0x80 && cp <= 0x9F) || cp == 0x2028 || cp == 0x2029 ||
           (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069);"""

UXXXX = r"""    const char e[6] = { '\\', 'u', HEX[(cp >> 12) & 15], HEX[(cp >> 8) & 15], HEX[(cp >> 4) & 15], HEX[cp & 15] };"""

TWO = r"""    if (s[0] >= 0xC2 && s[0] <= 0xDF && n >= 2 && (s[1] & 0xC0) == 0x80) {"""
THREE = r"""    if (s[0] >= 0xE0 && s[0] <= 0xEF && n >= 3 && (s[1] & 0xC0) == 0x80 && (s[2] & 0xC0) == 0x80) {"""
FOUR = r"""    if (s[0] >= 0xF0 && s[0] <= 0xF4 && n >= 4 && (s[1] & 0xC0) == 0x80 && (s[2] & 0xC0) == 0x80 && (s[3] & 0xC0) == 0x80) {"""
CP3 = r"""return (*cp >= 0x800 && (*cp < 0xD800 || *cp > 0xDFFF)) ? 3 : 0;"""
CP4 = r"""return (*cp >= 0x10000 && *cp <= 0x10FFFF) ? 4 : 0;"""

QUOTE = r"""        else if (c == '"' && json) put_str(b, "\\\"");"""
PLAIN = r"""        else if (c >= 0x20 && c != 0x7F) put_raw(b, (const char *)&c, 1);"""
INIT_SWAP = r"""    FILE *old = g_out;
    g_out = f;
    atomic_store(&g_json, json_mode != 0);
    atomic_store(&g_level, (int)min_level);
    pthread_mutex_unlock(&g_mu);"""
INIT_CLOSE = r"""    pthread_mutex_unlock(&g_mu);
    if (old && old != stderr) fclose(old);

    if (fell_back)"""
SHUT_CLOSE = r"""    pthread_mutex_unlock(&g_mu);
    if (old && old != stderr) fclose(old);
}"""
WRITE_LOCK = r"""    pthread_mutex_lock(&g_mu);
    if (g_out) {
        fwrite(text, 1, b.n, g_out);
        fflush(g_out);
    }
    pthread_mutex_unlock(&g_mu);"""

MUTANTS = [
 ("L01 name limit 256", "#define LOG_NAME_MAX  255", "#define LOG_NAME_MAX  256"),
 ("L02 name limit 254", "#define LOG_NAME_MAX  255", "#define LOG_NAME_MAX  254"),
 ("L03 line buffer too small for the worst case", "#define LOG_LINE_MAX  (6 * (CBAE_LOG_MSG_MAX + 2 * LOG_NAME_MAX) + 256)", "#define LOG_LINE_MAX  (4 * (CBAE_LOG_MSG_MAX + 2 * LOG_NAME_MAX) + 256)"),
 ("L04 initial level TRACE (equivalent: no sink yet)", "static _Atomic int     g_level = CBAE_LOG_NONE;", "static _Atomic int     g_level = CBAE_LOG_TRACE;"),
 ("L05 level name WARN", 'case CBAE_LOG_WARN:  return "WARN";', 'case CBAE_LOG_WARN:  return "WARNING";'),
 ("L06 level name ERROR", 'case CBAE_LOG_ERROR: return "ERROR";', 'case CBAE_LOG_ERROR: return "ERR";'),
 ("L07 put_raw: no clamp (equivalent: the buffer is sized for the worst case)", "    if (n > b->cap - b->n) n = b->cap - b->n;\n", ""),
 ("L08 put_xx: high digit", r"""    const char e[4] = { '\\', 'x', HEX[c >> 4], HEX[c & 15] };""", r"""    const char e[4] = { '\\', 'x', HEX[c & 15], HEX[c & 15] };"""),
 ("L09 put_xx: low digit", r"""    const char e[4] = { '\\', 'x', HEX[c >> 4], HEX[c & 15] };""", r"""    const char e[4] = { '\\', 'x', HEX[c >> 4], HEX[c >> 4] };"""),
 ("L10 hex digits upper case", 'static const char HEX[] = "0123456789abcdef";', 'static const char HEX[] = "0123456789ABCDEF";'),
 ("L11 put_uxxxx: first digit masked to 3 bits", UXXXX, UXXXX.replace("(cp >> 12) & 15", "(cp >> 12) & 7")),
 ("L12 put_uxxxx: second digit masked to 3 bits", UXXXX, UXXXX.replace("(cp >> 8) & 15", "(cp >> 8) & 7")),
 ("L13 put_uxxxx: third digit masked to 3 bits", UXXXX, UXXXX.replace("(cp >> 4) & 15", "(cp >> 4) & 7")),
 ("L14 put_uxxxx: last digit masked to 3 bits", UXXXX, UXXXX.replace("HEX[cp & 15] }", "HEX[cp & 7] }")),
 ("L15 2-byte: overlong C0/C1 lead accepted", TWO, TWO.replace("0xC2", "0xC0")),
 ("L16 2-byte: E0 lead taken as 2-byte", TWO, TWO.replace("0xDF", "0xE0")),
 ("L17 2-byte: continuation test weakened", TWO, TWO.replace("(s[1] & 0xC0) == 0x80", "(s[1] & 0x80) == 0x80")),
 ("L18 2-byte: may read the byte after the end", TWO, TWO.replace("n >= 2", "n >= 1")),
 ("L19 3-byte: F0 lead taken as 3-byte", THREE, THREE.replace("0xEF", "0xF0")),
 ("L20 3-byte: second byte not checked", THREE, THREE.replace(" && (s[1] & 0xC0) == 0x80", "")),
 ("L21 3-byte: third byte not checked", THREE, THREE.replace(" && (s[2] & 0xC0) == 0x80", "")),
 ("L22 3-byte: may read past the end", THREE, THREE.replace("n >= 3", "n >= 2")),
 ("L23 3-byte: overlong accepted", CP3, CP3.replace("*cp >= 0x800", "*cp >= 0x80")),
 ("L24 3-byte: surrogates accepted", CP3, CP3.replace("(*cp >= 0x800 && (*cp < 0xD800 || *cp > 0xDFFF))", "(*cp >= 0x800)")),
 ("L25 3-byte: U+DFFF accepted", CP3, CP3.replace("*cp > 0xDFFF", "*cp >= 0xDFFF")),
 ("L26 3-byte: U+D800 accepted", CP3, CP3.replace("*cp < 0xD800", "*cp <= 0xD800")),
 ("L27 3-byte: U+0800 refused", CP3, CP3.replace("*cp >= 0x800", "*cp > 0x800")),
 ("L28 4-byte: second byte not checked", FOUR, FOUR.replace(" && (s[1] & 0xC0) == 0x80", "")),
 ("L29 4-byte: last byte not checked", FOUR, FOUR.replace(" && (s[3] & 0xC0) == 0x80", "")),
 ("L30 4-byte: may read past the end", FOUR, FOUR.replace("n >= 4", "n >= 3")),
 ("L31 4-byte: lead up to F7 (equivalent: the code point test refuses F5..F7)", FOUR, FOUR.replace("0xF4", "0xF7")),
 ("L32 4-byte: overlong accepted", CP4, CP4.replace("*cp >= 0x10000", "*cp >= 0x1000")),
 ("L33 4-byte: U+10000 refused", CP4, CP4.replace("*cp >= 0x10000", "*cp > 0x10000")),
 ("L34 4-byte: U+10FFFF refused", CP4, CP4.replace("*cp <= 0x10FFFF", "*cp < 0x10FFFF")),
 ("L35 4-byte: above U+10FFFF accepted", CP4, CP4.replace("*cp <= 0x10FFFF", "*cp <= 0x110000")),
 ("L36 special: U+0080 not special", SPECIAL, SPECIAL.replace("cp >= 0x80 &&", "cp >= 0x81 &&")),
 ("L37 special: U+009F not special", SPECIAL, SPECIAL.replace("cp <= 0x9F", "cp <= 0x9E")),
 ("L38 special: U+2028 not special", SPECIAL, SPECIAL.replace("cp == 0x2028", "cp == 0x2027")),
 ("L39 special: U+2029 not special", SPECIAL, SPECIAL.replace("cp == 0x2029", "cp == 0x2030")),
 ("L40 special: U+202A not special", SPECIAL, SPECIAL.replace("cp >= 0x202A", "cp >= 0x202B")),
 ("L41 special: U+202F special", SPECIAL, SPECIAL.replace("cp <= 0x202E", "cp <= 0x202F")),
 ("L42 special: U+2065 special", SPECIAL, SPECIAL.replace("cp >= 0x2066", "cp >= 0x2065")),
 ("L43 special: U+206A special", SPECIAL, SPECIAL.replace("cp <= 0x2069", "cp <= 0x206A")),
 ("L44 special: nothing is special", SPECIAL, "    return false;"),
 ("L45 escape: names and messages not cut", "    const size_t n = strnlen(s, max);", "    const size_t n = strlen(s);"),
 ("L46 escape: 2-byte characters taken byte by byte", "if (seq > 1) {", "if (seq > 2) {"),
 ("L47 escape: special test inverted", ESCAPE_SEQ, ESCAPE_SEQ.replace("if (is_special(cp))", "if (!is_special(cp))")),
 ("L48 escape: invalid byte raw in text mode", "if (seq == 0) {", "if (seq == 0 && json) {"),
 ("L49 escape: invalid byte, modes swapped", "if (json) put_uxxxx(b, 0xFFFD); else put_xx(b, c);", "if (!json) put_uxxxx(b, 0xFFFD); else put_xx(b, c);"),
 ("L50 escape: backslash not doubled", r"""        } else if (c == '\\') put_str(b, "\\\\");""", r"""        } else if (c == '\\') put_str(b, "\\");"""),
 ("L51 escape: quote escaped in text mode too", QUOTE, QUOTE.replace(" && json", "")),
 ("L52 escape: quote escaped in the wrong mode", QUOTE, QUOTE.replace("&& json", "&& !json")),
 ("L53 escape: space is a control character", PLAIN, PLAIN.replace("c >= 0x20", "c > 0x20")),
 ("L54 escape: 0x1F is printable", PLAIN, PLAIN.replace("c >= 0x20", "c >= 0x1F")),
 ("L55 escape: DEL is printable", PLAIN, PLAIN.replace(" && c != 0x7F", "")),
 ("L56 escape: tilde is a control character", PLAIN, PLAIN.replace("c != 0x7F", "c != 0x7E")),
 ("L57 escape: text mode controls get JSON escapes", "        else if (!json) put_xx(b, c);", "        else if (0) put_xx(b, c);"),
 ("L58 escape: JSON controls get \\x", "            default:   put_uxxxx(b, c);", "            default:   put_xx(b, c);"),
 ("L59 escape: JSON newline long form", r"""            case '\n': put_str(b, "\\n"); break;""", ""),
 ("L60 escape: JSON return long form", r"""            case '\r': put_str(b, "\\r"); break;""", ""),
 ("L61 escape: JSON tab long form", r"""            case '\t': put_str(b, "\\t"); break;""", ""),
 ("L62 escape: JSON backspace long form", r"""            case '\b': put_str(b, "\\b"); break;""", ""),
 ("L63 escape: JSON form feed long form", r"""            case '\f': put_str(b, "\\f"); break;""", ""),
 ("L64 init: an empty path is a path (equivalent: fopen(\"\") fails and an empty path is not reported)", "    if (path && *path) {\n        f = fopen(path, \"a\");", "    if (path) {\n        f = fopen(path, \"a\");"),
 ("L65 init: no path is a failure", "    const bool fell_back = !f && path && *path;", "    const bool fell_back = !f;"),
 ("L66 init: no stderr fallback", "    if (!f) f = stderr;\n", ""),
 ("L67 init: JSON flag inverted", "    atomic_store(&g_json, json_mode != 0);", "    atomic_store(&g_json, json_mode == 0);"),
 ("L68 init: level off by one", "    atomic_store(&g_level, (int)min_level);", "    atomic_store(&g_level, (int)min_level + 1);"),
 ("L69 init: the old file is not closed", INIT_CLOSE, INIT_CLOSE.replace("    if (old && old != stderr) fclose(old);\n", "")),
 ("L70 init: stderr may be closed", INIT_CLOSE, INIT_CLOSE.replace("if (old && old != stderr) fclose(old);", "if (old) fclose(old);")),
 ("L71 init: the sink is swapped outside the lock", INIT_SWAP, "    FILE *old = g_out;\n    pthread_mutex_unlock(&g_mu);\n    g_out = f;\n    atomic_store(&g_json, json_mode != 0);\n    atomic_store(&g_level, (int)min_level);"),
 ("L72 init: errno not kept", "        if (!f) open_errno = errno;", "        if (!f) open_errno = 0;"),
 ("L73 init: the warning is INFO", "    if (fell_back) cbae_log_write(CBAE_LOG_WARN, __FILE__", "    if (fell_back) cbae_log_write(CBAE_LOG_INFO, __FILE__"),
 ("L74 shutdown: the sink is not forgotten", "    g_out = NULL;\n    atomic_store(&g_level, CBAE_LOG_NONE);", "    atomic_store(&g_level, CBAE_LOG_NONE);"),
 ("L75 shutdown: the level is not reset (equivalent: no sink)", "    g_out = NULL;\n    atomic_store(&g_level, CBAE_LOG_NONE);", "    g_out = NULL;"),
 ("L76 shutdown: the file is not closed", SHUT_CLOSE, SHUT_CLOSE.replace("    if (old && old != stderr) fclose(old);\n", "")),
 ("L77 write: levels below TRACE pass the range test", "if ((int)level < (int)CBAE_LOG_TRACE || (int)level >= (int)CBAE_LOG_NONE) return;", "if ((int)level >= (int)CBAE_LOG_NONE) return;"),
 ("L78 write: level NONE is a message level", "|| (int)level >= (int)CBAE_LOG_NONE) return;", "|| (int)level > (int)CBAE_LOG_NONE) return;"),
 ("L79 write: the minimum level is exclusive", "    if ((int)level < atomic_load(&g_level)) return;", "    if ((int)level <= atomic_load(&g_level)) return;"),
 ("L80 write: message not cleared before formatting", "    msg[0] = '\\0';\n", ""),
 ("L81 write: an empty message is a failure", "if (fmt && vsnprintf(msg, sizeof msg, fmt, args) < 0)", "if (fmt && vsnprintf(msg, sizeof msg, fmt, args) <= 0)"),
 ("L82 write: a NULL format is formatted", "if (fmt && vsnprintf(msg, sizeof msg, fmt, args) < 0)", "if (vsnprintf(msg, sizeof msg, fmt, args) < 0)"),
 ("L83 write: a failed format is kept", 'strcpy(msg, "(unformattable log message)");', "{}"),
 ("L84 write: local time", "gmtime_r(&now.tv_sec, &tm)", "localtime_r(&now.tv_sec, &tm)"),
 ("L85 write: no Z", r"""snprintf(ts + n, sizeof ts - n, ".%03ldZ", now.tv_nsec / 1000000);""", r"""snprintf(ts + n, sizeof ts - n, ".%03ld", now.tv_nsec / 1000000);"""),
 ("L86 write: hundredths of a second", r"""snprintf(ts + n, sizeof ts - n, ".%03ldZ", now.tv_nsec / 1000000);""", r"""snprintf(ts + n, sizeof ts - n, ".%03ldZ", now.tv_nsec / 100000);"""),
 ("L87 write: NULL file", 'put_escaped(&b, file ? file : "?", LOG_NAME_MAX, true);', "put_escaped(&b, file, LOG_NAME_MAX, true);"),
 ("L88 write: NULL function", 'put_escaped(&b, func ? func : "?", LOG_NAME_MAX, false);', "put_escaped(&b, func, LOG_NAME_MAX, false);"),
 ("L89 write: JSON key", r"""put_str(&b, ",\"func\":\"");""", r"""put_str(&b, ",\"function\":\"");"""),
 ("L90 write: text separator", """put_str(&b, "  "); put_escaped(&b, file ? file : "?", LOG_NAME_MAX, false);""", """put_str(&b, " "); put_escaped(&b, file ? file : "?", LOG_NAME_MAX, false);"""),
 ("L91 write: text message separator", """put_str(&b, ")  "); put_escaped(&b, msg, sizeof msg, false);""", """put_str(&b, ") "); put_escaped(&b, msg, sizeof msg, false);"""),
 ("L92 write: line one byte short", "    text[b.n++] = '\\n';", "    text[b.n++] = ' ';"),
 ("L93 write: the last byte of the line is not written", "        fwrite(text, 1, b.n, g_out);", "        fwrite(text, 1, b.n - 1, g_out);"),
 ("L94 write: no flush", "        fflush(g_out);\n", ""),
 ("L95 write: no lock", WRITE_LOCK, WRITE_LOCK.replace("    pthread_mutex_lock(&g_mu);\n", "").replace("    pthread_mutex_unlock(&g_mu);", "")),
 ("L96 write: sink used without a test", "    if (g_out) {\n        fwrite(text, 1, b.n, g_out);", "    if (1) {\n        fwrite(text, 1, b.n, g_out);"),
]
