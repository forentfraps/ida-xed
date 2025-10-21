#include <pro.h> // must be first
                 //
                 //
#include <bytes.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <ua.hpp>

extern "C" {
#include <xed/xed-interface.h>
}

namespace xedwrap {
static bool g_inited = false;

static void ensure_init() {
  if (!g_inited) {
    xed_tables_init();
    g_inited = true;
  }
}

static xed_state_t make_state() {
  xed_state_t state;
  xed_state_zero(&state);
  if (inf_is_64bit()) {
    state.mmode = XED_MACHINE_MODE_LONG_64;
    state.stack_addr_width = XED_ADDRESS_WIDTH_64b;
  } else {
    state.mmode = XED_MACHINE_MODE_LEGACY_32;
    state.stack_addr_width = XED_ADDRESS_WIDTH_32b;
  }
  return state;
}

static bool decode_at(ea_t ea, xed_state_t &state, qstring &out_text,
                      uint32 &out_len, bool &out_diverts) {
  out_text.clear();
  out_len = 0;
  out_diverts = false;

  uint8 buf[16] = {0};
  ssize_t got = get_bytes(buf, sizeof(buf), ea);
  if (got <= 0)
    return false;

  xed_decoded_inst_t xedd;
  xed_decoded_inst_zero_set_mode(&xedd, &state);

  xed_error_enum_t xerr = xed_decode(&xedd, buf, (unsigned)got);
  if (xerr != XED_ERROR_NONE)
    return false;

  out_len = xed_decoded_inst_get_length(&xedd);

  // CF diversion: branches/calls/returns/interrupts/sys*
  bool div = false;
  const xed_category_enum_t cat = xed_decoded_inst_get_category(&xedd);
  switch (cat) {
  case XED_CATEGORY_COND_BR:
  case XED_CATEGORY_UNCOND_BR:
  case XED_CATEGORY_CALL:
  case XED_CATEGORY_RET:
  case XED_CATEGORY_INTERRUPT:
    div = true;
    break;
  default:
    break;
  }
  if (!div) {
    const xed_iclass_enum_t ic = xed_decoded_inst_get_iclass(&xedd);
    switch (ic) {
    case XED_ICLASS_SYSCALL:
    case XED_ICLASS_SYSRET:
    case XED_ICLASS_IRET:
    case XED_ICLASS_IRETD:
    case XED_ICLASS_IRETQ:
      div = true;
      break;
    default:
      break;
    }
  }
  out_diverts = div;

  char tmp[128];
  if (!xed_format_context(XED_SYNTAX_INTEL, &xedd, tmp, sizeof(tmp),
                          (xed_uint64_t)ea, nullptr, nullptr))
    return false;

  out_text = tmp;
  return true;
}
} // namespace xedwrap

static const char *ACTION_NAME = "xed:annotate";
static const char *ACTION_LABEL = "Decode with Intel XED";

static bool materialize_xed_insn(ea_t ea, size_t ilen,
                                 const qstring &xed_line) {
  del_items(ea, DELIT_SIMPLE, ilen);

  if (!create_insn(ea))
    return false;

  set_manual_insn(ea, xed_line.c_str());
  return true;
}

static void run_linear_from_cursor_until_divert() {
  xedwrap::ensure_init();
  xed_state_t st = xedwrap::make_state();

  ea_t start = get_screen_ea();
  if (!is_mapped(start)) {
    warning("Screen EA is unmapped.");
    return;
  }

  segment_t *seg = getseg(start);
  ea_t limit = seg ? seg->end_ea : start + 0x2000; // safety cap

  ea_t ea = start;
  int n_ok = 0, n_manual = 0, n_fail = 0;

  show_wait_box("XED: assembling from %a ...", start);

  while (ea < limit && is_mapped(ea)) {
    qstring text;
    uint32 ilen = 0;
    bool div = false;

    if (xedwrap::decode_at(ea, st, text, ilen, div) && ilen > 0) {

      if (materialize_xed_insn(ea, ilen, text)) {
        ++n_ok;
      } else {
        set_cmt(ea, text.c_str(), /*repeatable=*/false);
        ++n_manual;
      }

      ea += ilen;
      if (div)
        break;
    } else {
      ++n_fail;
      ea += 1;
    }
  }

  hide_wait_box();
  msg("XED: from %a — code:%d manual:%d undecoded:%d\n", start, n_ok, n_manual,
      n_fail);
}

struct xed_action_handler_t : public action_handler_t {
  int idaapi activate(action_activation_ctx_t *) override {
    run_linear_from_cursor_until_divert();
    return 1;
  }
  action_state_t idaapi update(action_update_ctx_t *) override {
    return AST_ENABLE_FOR_WIDGET;
  }
};

struct xed_plugmod_t : public plugmod_t {
  bool idaapi run(size_t) override {
    xed_action_handler_t h;
    action_activation_ctx_t ctx{};
    h.activate(&ctx);
    return true;
  }
};

plugmod_t *idaapi init(void) {
  char pname[16] = {};
  if (!inf_get_procname(pname, sizeof(pname)))
    return PLUGIN_SKIP;
  if (strcmp(pname, "metapc") != 0)
    return PLUGIN_SKIP;

  static xed_action_handler_t handler;
  const action_desc_t desc =
      ACTION_DESC_LITERAL(ACTION_NAME, ACTION_LABEL, &handler, "Alt+X",
                          "Linear XED decode from cursor; assemble to real "
                          "instructions; stop on CF divert.",
                          -1);
  register_action(desc);
  attach_action_to_menu("Edit/Plugins/", ACTION_NAME, SETMENU_APP);
  return new xed_plugmod_t();
}

plugin_t PLUGIN = {IDP_INTERFACE_VERSION,
                   PLUGIN_MULTI,
                   init,
                   nullptr,
                   nullptr,
                   "Intel XED annotator",
                   "Linear XED decode from cursor; tries to assemble "
                   "instructions; stops on control-flow diversion.",
                   "Decode with Intel XED",
                   ""};
