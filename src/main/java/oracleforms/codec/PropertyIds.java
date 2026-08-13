package oracleforms.codec;

import java.util.Map;
import java.util.Set;

/**
 * The Oracle Forms property id table, ported verbatim from the reference implementation
 * (3erk1n/oracle-forms-decoder). 466 entries.
 *
 * <p>The reverse lookup is precomputed once. The reference rebuilt it by linear scan on every
 * property of every message of every render; see architecture &sect;7.11.
 */
public final class PropertyIds {

    private static final Map<Integer, String> NAMES = buildNames();
    private static final Map<String, Integer> IDS = buildIds();

    /** Ids whose string values carry credentials or other secrets. */
    public static final Set<Integer> SENSITIVE_IDS = Set.of(
            131, 433, 434, 435, 439, 440, 441, 444, 445);

    private PropertyIds() {
    }

    /** Name for a property id, or {@code ID_<n>} when the id is not in the table. */
    public static String name(int id) {
        String known = NAMES.get(id);
        return known != null ? known : "ID_" + id;
    }

    /** True when {@link #name(int)} would return a real name rather than a synthesised one. */
    public static boolean isKnown(int id) {
        return NAMES.containsKey(id);
    }

    /** Id for a property name, or {@code -1} if unknown. Names are unique across the table. */
    public static int id(String name) {
        return IDS.getOrDefault(name, -1);
    }

    public static boolean isSensitive(int id) {
        return SENSITIVE_IDS.contains(id);
    }

    public static int size() {
        return NAMES.size();
    }

    private static Map<Integer, String> buildNames() {
        Map<Integer, String> m = new java.util.HashMap<>(932);
        put0(m);
        put1(m);
        put2(m);
        put3(m);
        put4(m);
        put5(m);
        return Map.copyOf(m);
    }

    private static Map<String, Integer> buildIds() {
        Map<String, Integer> m = new java.util.HashMap<>(932);
        NAMES.forEach((id, name) -> m.put(name, id));
        return Map.copyOf(m);
    }

    private static void put0(Map<Integer, String> m) {
        m.put(16, "TAG");
        m.put(101, "APPLICATION");
        m.put(102, "FORM_MODULE");
        m.put(103, "NAME");
        m.put(104, "PARENT");
        m.put(105, "CANCEL");
        m.put(106, "CANCEL_LABEL");
        m.put(107, "CANCEL_MNEMONIC");
        m.put(108, "COLTITLE");
        m.put(109, "COLWIDTH");
        m.put(110, "CONNECT_LABEL");
        m.put(111, "CONNECT_MNEMONIC");
        m.put(112, "FIND_LABEL");
        m.put(113, "FIND_MNEMONIC");
        m.put(114, "ICON_FILENAME");
        m.put(115, "ALIGNMENT");
        m.put(116, "LABEL");
        m.put(117, "MAX_LENGTH");
        m.put(118, "NO_LABEL");
        m.put(119, "OK_LABEL");
        m.put(120, "OK_MNEMONIC");
        m.put(121, "RANGE");
        m.put(122, "ROWVAL");
        m.put(123, "SCROLL");
        m.put(124, "SEARCH_LABEL");
        m.put(125, "SEARCH_MNEMONIC");
        m.put(126, "SIZE");
        m.put(127, "STATUS");
        m.put(128, "STYLE");
        m.put(129, "TITLE");
        m.put(130, "CANVASTYPE");
        m.put(131, "VALUE");
        m.put(132, "WINDOW");
        m.put(133, "CLEARDAMAGE");
        m.put(134, "UI_PARENT");
        m.put(135, "LOCATION");
        m.put(136, "INNERSIZE");
        m.put(137, "OUTERSIZE");
        m.put(138, "CANVASMOVABLE");
        m.put(139, "CANVASORIGIN");
        m.put(140, "MNEMONIC");
        m.put(141, "NAVIGABLE");
        m.put(142, "TABSTOP");
        m.put(143, "GROUP");
        m.put(144, "ENABLED");
        m.put(145, "EVENTMODE");
        m.put(146, "FOREGROUND");
        m.put(147, "BACKGROUND");
        m.put(148, "BGPATTERN");
        m.put(149, "FONT");
        m.put(150, "BORDERUSE");
        m.put(151, "BORDERWD");
        m.put(152, "BORDER_BEVEL");
        m.put(153, "BOUNDS");
        m.put(154, "BORDER");
        m.put(155, "VISIBLERECT");
        m.put(156, "ISMAPPED");
        m.put(157, "ISVISIBLE");
        m.put(158, "USAGE");
        m.put(159, "BASELINE");
        m.put(160, "PRIVATE");
        m.put(161, "HIGHLIGHTFOCUS");
        m.put(162, "BMUNPROTECTED");
        m.put(163, "EVENTMASK");
        m.put(164, "MAPREQUEST");
        m.put(165, "LANGUAGE_DIRECTION");
        m.put(166, "DIRCHANGE");
        m.put(167, "VALIDKEYS");
        m.put(168, "DEFAULTKEYS");
        m.put(169, "DRAWTHRU");
        m.put(170, "CANVASHANDLE");
        m.put(171, "DLGOK");
        m.put(172, "MESSAGE");
        m.put(173, "VISIBLE");
        m.put(174, "FOCUS");
        m.put(175, "KEY");
        m.put(176, "SKEY");
        m.put(177, "MOVEABOVE");
        m.put(178, "MOVETOP");
        m.put(179, "DAMAGE");
    }

    private static void put1(Map<Integer, String> m) {
        m.put(180, "MOUSEDOWN");
        m.put(181, "MOUSEUP");
        m.put(182, "MOUSEENTER");
        m.put(183, "MOUSEEXIT");
        m.put(184, "MOUSEMOVE");
        m.put(185, "MOUSEDOWN_POS");
        m.put(186, "MOUSEDOWN_MOD");
        m.put(187, "AUTOSCROLL");
        m.put(188, "OBSCURE");
        m.put(189, "OPTIMIZED_FOCUS");
        m.put(190, "SPCL_FOREGROUND");
        m.put(191, "SPCL_BACKGROUND");
        m.put(192, "CWIDTH");
        m.put(193, "CURSOR_POSITION");
        m.put(194, "EDITABLE");
        m.put(195, "SELECTION");
        m.put(196, "ALWAYSHOME");
        m.put(197, "SECURE");
        m.put(198, "AUTOSKIP");
        m.put(199, "CASE_FOLD");
        m.put(200, "TYPEOVERMODE");
        m.put(201, "RENDER");
        m.put(202, "CAN_TAKE_FOCUS");
        m.put(203, "HAS_LOV");
        m.put(204, "REQUIRED_CHANGE");
        m.put(205, "REPLACES");
        m.put(206, "CLRDIRTY");
        m.put(207, "CHEIGHT");
        m.put(208, "WRAP_STYLE");
        m.put(209, "VSBARPOLICY");
        m.put(210, "CONTENT");
        m.put(211, "DRAWN_AUTOSCROLLED");
        m.put(212, "DRAWN_SLOWDRAW");
        m.put(213, "DRAWN_CANVASUSAGE");
        m.put(214, "DRAWN_RESIZED");
        m.put(215, "DRAWN_MDIFLAG");
        m.put(216, "WINDOW_CLOSE");
        m.put(217, "WINDOW_CONTENT");
        m.put(218, "WINDOW_HSA");
        m.put(219, "WINDOW_VSA");
        m.put(220, "WINDOW_HTBA");
        m.put(221, "WINDOW_VTBA");
        m.put(222, "WINDOW_MODALITY");
        m.put(223, "WINDOW_MOUSERELATIVE");
        m.put(224, "WINDOW_MIN_SIZE");
        m.put(225, "WINDOW_MAX_SIZE");
        m.put(226, "WINDOW_INC_SIZE");
        m.put(227, "WINDOW_CAN_RESIZE");
        m.put(228, "WINDOW_CAN_CLOSE");
        m.put(229, "WINDOW_CAN_MOVE");
        m.put(230, "WINDOW_CAN_MINIMIZE");
        m.put(231, "WINDOW_CAN_MAXIMIZE");
        m.put(232, "WINDOW_CAN_TITLE");
        m.put(233, "WINDOW_ICON_IMAGE");
        m.put(234, "WINDOW_APP_MENU");
        m.put(235, "WINDOW_NAVIGATION");
        m.put(236, "WINSYS_CURSOR");
        m.put(237, "WINDOW_COLORPAL");
        m.put(238, "WINDOW_COLORMAPREDRAW");
        m.put(239, "WINDOW_MENU");
        m.put(240, "WINDOW_BMPAINTABLE");
        m.put(241, "WINDOW_LEADER");
        m.put(242, "WINDOW_MAXIMIZED");
        m.put(243, "WINDOW_ICONIFIED");
        m.put(244, "WINDOW_USE3D");
        m.put(245, "WINDOW_PRINT");
        m.put(246, "WINDOW_RAISE");
        m.put(247, "WINDOW_ACTIVATED");
        m.put(248, "WINDOW_MDI_VTOOLBAR");
        m.put(249, "WINDOW_MDI_HTOOLBAR");
        m.put(250, "SB_SIZE");
        m.put(251, "SB_LINEINCR");
        m.put(252, "SB_PAGEINCR");
        m.put(253, "SB_SCROLLEE");
        m.put(254, "SB_HORIZONTAL");
        m.put(255, "SB_REVERSEDIR");
        m.put(256, "SB_ACTION");
        m.put(257, "SBOX_CONTENT");
        m.put(258, "SBOX_HSA");
        m.put(259, "SBOX_VSA");
    }

    private static void put2(Map<Integer, String> m) {
        m.put(260, "SBOX_CONTENTSIZE");
        m.put(261, "SBOX_HLABEL");
        m.put(262, "SBOX_VLABEL");
        m.put(263, "INITIAL_RESOLUTION");
        m.put(264, "INITIAL_DISP_SIZE");
        m.put(265, "INITIAL_CMDLINE");
        m.put(266, "INITIAL_COLOR_DEPTH");
        m.put(267, "INITIAL_SCALE_INFO");
        m.put(268, "INITIAL_VERSION");
        m.put(269, "VERSION_TOO_OLD");
        m.put(270, "VERSION_TOO_NEW");
        m.put(271, "INITIAL_ENCRYPTKEY");
        m.put(272, "SUPPORT_SURROGATE_PAIRS");
        m.put(273, "WINSYS_TERMINALFILE");
        m.put(274, "WINSYS_DEVICENAME");
        m.put(275, "WINSYS_NEEDAPPMENU");
        m.put(276, "WINSYS_SDI");
        m.put(277, "WINSYS_TRANSIENTMENU");
        m.put(278, "WINSYS_BOOTKEYCS");
        m.put(279, "MAX_BYTES_PER_CHAR");
        m.put(280, "WINSYS_DRAWINGDIR");
        m.put(281, "WINSYS_LAYOUTDIR");
        m.put(282, "WINSYS_BEEP");
        m.put(283, "WINSYS_HYPERLINK");
        m.put(284, "WINSYS_COLOR_ADD");
        m.put(285, "WINSYS_CONSOLE_MSG");
        m.put(286, "WINSYS_WORKING_MSG");
        m.put(287, "WINSYS_FONT_ADD");
        m.put(288, "WINSYS_PLAY_TEST");
        m.put(290, "WINSYS_LOCALESUPPORT");
        m.put(291, "WINSYS_REQUIREDVA_LIST");
        m.put(292, "WINSYS_SYNC_BUILTIN");
        m.put(293, "ALERT_NO_MNEMONIC");
        m.put(294, "ALERT_ICON");
        m.put(295, "ALERT_BUTTONS");
        m.put(296, "ALERT_DEFAULT_BUTTON");
        m.put(297, "BP_TYPE");
        m.put(298, "BP_PARENT");
        m.put(299, "BP_STRINGVAL");
        m.put(300, "BP_BASELINE");
        m.put(301, "BP_HALIGN");
        m.put(302, "BP_VALIGN");
        m.put(303, "BP_LSTART");
        m.put(304, "BP_LEND");
        m.put(305, "BP_FOREFILLCOL");
        m.put(306, "BP_BACKFILLCOL");
        m.put(307, "BP_FOREEDGECOL");
        m.put(308, "BP_BACKEDGECOL");
        m.put(309, "BP_TEXTCOL");
        m.put(310, "BP_LINETHICK");
        m.put(311, "BP_RRECT");
        m.put(312, "BP_EDGEPATTERN");
        m.put(313, "BP_FILLPATTERN");
        m.put(314, "BP_LINE_BEVEL");
        m.put(315, "BP_FONT");
        m.put(316, "BP_NUMCHUNKS");
        m.put(317, "BP_CHUNK");
        m.put(318, "BP_SCREEN_HORIZONTAL");
        m.put(319, "BP_SCREEN_VERTICAL");
        m.put(320, "BP_VGS_HORIZONTAL");
        m.put(321, "BP_VGS_VERTICAL");
        m.put(322, "BP_VGS_VERSION");
        m.put(323, "IS_CANCEL");
        m.put(324, "IS_DEFAULT");
        m.put(325, "PRESSED");
        m.put(326, "IMAGE");
        m.put(327, "PLIST_LISTINDEX");
        m.put(328, "PLIST_LISTITEM");
        m.put(329, "PLIST_ADDLISTITEM");
        m.put(330, "PLIST_DELLISTITEM");
        m.put(331, "PLIST_DELLIST");
        m.put(332, "PLIST_LISTCLOSED");
        m.put(333, "COUNT");
        m.put(334, "SELECTEDINDEX");
        m.put(335, "SELECT");
        m.put(336, "DESELECT");
        m.put(337, "MAKEVISIBLE");
        m.put(338, "COMBOBOX_USERITEM");
        m.put(339, "USERTEXT");
        m.put(340, "TLIST_NOSELECTION");
    }

    private static void put3(Map<Integer, String> m) {
        m.put(341, "TLIST_ACTIVATED");
        m.put(342, "RB_AUTOTABSTOP");
        m.put(343, "RB_AUTOCOORD");
        m.put(344, "RADIOGROUP");
        m.put(345, "LOCALSTATE");
        m.put(346, "GROUPLEADER");
        m.put(347, "STBAR_ADDLAMP");
        m.put(348, "STBAR_MSGLINE");
        m.put(349, "STBAR_LAMP_INDEX");
        m.put(350, "STBAR_LAMP_VALUE");
        m.put(351, "STBAR_SHOW_WORKING");
        m.put(352, "STBAR_BLANK_MSG");
        m.put(353, "STBAR_MAKE_CURRENT");
        m.put(354, "MENU_MENUITEM");
        m.put(355, "MENU_ACCEL_CODE");
        m.put(356, "MENU_ACCELERATOR");
        m.put(357, "MENU_ACCEL_MOD");
        m.put(358, "MENU_HELP");
        m.put(359, "MENU_HIDDEN");
        m.put(360, "MENU_ICON");
        m.put(361, "MENU_ID");
        m.put(362, "MENU_STARTGROUP");
        m.put(363, "MENU_STATE");
        m.put(364, "MENU_SUBMENU");
        m.put(365, "MENU_TEAROFF");
        m.put(366, "MENU_ENDSUBMENU");
        m.put(367, "MENU_MENUUPDATE");
        m.put(368, "MENU_POPVIEW");
        m.put(369, "MENU_POPXY");
        m.put(370, "MENU_CREATEUI");
        m.put(371, "MENU_FLAGS");
        m.put(372, "MENU_NOSMARTBAR");
        m.put(373, "TIMER_SCHEDULE");
        m.put(374, "TIMER_EXPIRED");
        m.put(375, "TIMER_CREATE");
        m.put(376, "FONT_CHARSET");
        m.put(377, "FONT_SIZE");
        m.put(378, "FONT_STYLE");
        m.put(379, "FONT_WEIGHT");
        m.put(380, "FONT_WIDTH");
        m.put(381, "FONT_IMAGETEXT");
        m.put(382, "FONT_KERNING");
        m.put(383, "FONT_NAME");
        m.put(384, "IMAGE_URL");
        m.put(385, "IMAGE_VALUE");
        m.put(386, "SCALE");
        m.put(387, "SCROLL_STYLE");
        m.put(388, "IMAGE_SELECTRECT");
        m.put(389, "IMAGE_SELECTALL");
        m.put(390, "IMAGE_CUT");
        m.put(391, "IMAGE_COPY");
        m.put(392, "IMAGE_PASTE");
        m.put(393, "IMAGE_QUALITY");
        m.put(394, "IMAGE_DITHER");
        m.put(395, "SCROLL_POSITION");
        m.put(396, "VIEWPORT_SIZE");
        m.put(397, "CLASSNAME");
        m.put(398, "EVENT");
        m.put(399, "EVENTNAME");
        m.put(400, "EVENT_ARGNAME");
        m.put(401, "EVENT_ARGVALUE");
        m.put(402, "CUSTOM_PROPERTY");
        m.put(403, "CUSTOM_PROPERTY_NAME");
        m.put(404, "CUSTOM_PROPERTY_VALUE");
        m.put(405, "CLIPBOARD_CLEAR");
        m.put(406, "CLIPBOARD_GET");
        m.put(407, "CLIPBOARD_SET");
        m.put(408, "CLIPBOARD_LENGTH");
        m.put(409, "POPUPHELP_STRING");
        m.put(410, "POPUPHELP_ID");
        m.put(411, "TAB_TOPPAGE");
        m.put(412, "TAB_TABSIDE");
        m.put(413, "TAB_PAGEINFO");
        m.put(414, "TAB_PAGENUM");
        m.put(415, "TAB_PAGEID");
        m.put(416, "PROMPTLIST_CANVAS");
        m.put(417, "PROMPTLIST_ADD_PROMPT_ID");
        m.put(418, "PROMPTLIST_REMOVE_PROMPT");
        m.put(419, "PROMPTLIST_UPDATE_PROMPT_ID");
        m.put(420, "PROMPTLIST_DONE_PROMPT");
    }

    private static void put4(Map<Integer, String> m) {
        m.put(421, "PROMPT_ENUM");
        m.put(422, "PROMPT_EOF");
        m.put(423, "PROMPT_AOF");
        m.put(424, "PROMPT_LINECOUNT");
        m.put(425, "PROMPT_COLORNUM");
        m.put(426, "PROMPT_FONTNUM");
        m.put(427, "PROMPT_ITEMPOS");
        m.put(428, "PROMPT_ITEMSIZE");
        m.put(429, "PROMPT_BGPATTERN");
        m.put(430, "LOGON_USERNAME_LABEL");
        m.put(431, "LOGON_PASSWORD_LABEL");
        m.put(432, "LOGON_DATABASE_LABEL");
        m.put(433, "LOGON_USERNAME_VALUE");
        m.put(434, "LOGON_PASSWORD_VALUE");
        m.put(435, "LOGON_DATABASE_VALUE");
        m.put(436, "LOGON_OLDPASSWORD_LABEL");
        m.put(437, "LOGON_NEWPASSWORD_LABEL");
        m.put(438, "LOGON_RETYPE_PASSWORD_LABEL");
        m.put(439, "LOGON_OLDPASSWORD_VALUE");
        m.put(440, "LOGON_NEWPASSWORD_VALUE");
        m.put(441, "LOGON_RETYPE_PASSWORD_VALUE");
        m.put(442, "DISPERR_SQL_LABEL");
        m.put(443, "DISPERR_ERROR_LABEL");
        m.put(444, "DISPERR_SQL_VALUE");
        m.put(445, "DISPERR_ERROR_VALUE");
        m.put(446, "LOV_ROWS");
        m.put(447, "LOV_AUTOSIZECOLS");
        m.put(448, "LOV_DEFINECOL");
        m.put(449, "LOV_COLRALIGN");
        m.put(450, "LOV_SELECTION");
        m.put(451, "LOV_REQUEST_ROW");
        m.put(452, "LOV_AUTOREDUCECHAR");
        m.put(453, "LOV_UNREDUCE");
        m.put(454, "LOV_FIND_VAL");
        m.put(455, "LOV_LONGLIST_LABEL");
        m.put(456, "LOV_NOTLONGLIST");
        m.put(457, "EDITOR_BOTTOM_TITLE");
        m.put(458, "EDITOR_VALUE_REQD");
        m.put(459, "EDITOR_VSCROLL");
        m.put(460, "EDITOR_SCROLLBAR");
        m.put(461, "EDITOR_MULTILINE");
        m.put(462, "EDITOR_PESRCHREP");
        m.put(463, "EDITOR_PESRCHFOR");
        m.put(464, "EDITOR_PEREPLWTH");
        m.put(465, "EDITOR_PEREPLACE");
        m.put(466, "EDITOR_PEREPALL");
        m.put(467, "EDITOR_PECONTBEGIN");
        m.put(468, "EDITOR_PECONTINUE");
        m.put(469, "EDITOR_PEENDREG");
        m.put(470, "EDITOR_PENOMATCH");
        m.put(471, "PARAM_MUSTFILL");
        m.put(472, "PARAM_REQUIRED");
        m.put(473, "PARAM_NUM_DISPLAYED");
        m.put(474, "PARAM_ERR_REQUIRED");
        m.put(475, "PARAM_ERR_MUSTFILL");
        m.put(476, "EVENT_ALERT_DISMISS");
        m.put(477, "EVENT_MENU");
        m.put(478, "EVENT_WINSYS");
        m.put(479, "EVENT_SCROLL");
        m.put(480, "EVENT_WINDOW_FINAL");
        m.put(481, "EVENT_SHOWOPTIONS");
        m.put(482, "EVENT_DELIMAGE");
        m.put(483, "EVENT_USER_DEFINED");
        m.put(484, "NODE_STATE");
        m.put(485, "NUM_CHILD_NODES");
        m.put(486, "NUM_SELECTED");
        m.put(487, "SELECT_NODE");
        m.put(488, "EVENT_SELECTED");
        m.put(489, "EVENT_EXPANDED");
        m.put(490, "EVENT_COLLAPSED");
        m.put(491, "EVENT_ACTIVATED");
        m.put(492, "EVENT_DESELECTED");
        m.put(493, "REQUESTED_EVENTS");
        m.put(494, "ADD_NODE");
        m.put(495, "DELETE_NODE");
        m.put(496, "MULTI_SELECT");
        m.put(497, "SHOW_LINES");
        m.put(498, "SHOW_SYMBOLS");
        m.put(499, "ALTER_NODE");
        m.put(500, "NODE_ID");
    }

    private static void put5(Map<Integer, String> m) {
        m.put(501, "TREE_FREEZE");
        m.put(502, "NODE_ANCHOR");
        m.put(503, "NODE_OFFSET");
        m.put(504, "NODE_SELECTION");
        m.put(505, "NODE_DATA");
        m.put(506, "NUM_CHILDREN");
        m.put(507, "RESET_CHILDREN");
        m.put(508, "JHELP_TOPICID");
        m.put(509, "HBOOK_TITLE");
        m.put(510, "SERVER_USER_PARAMS");
        m.put(511, "ALL_PROPERTIES");
        m.put(512, "ALL_LISTENERS");
        m.put(513, "ACCESSIBILITY_SUPPORT");
        m.put(514, "ACCESSIBILITY_DESC");
        m.put(515, "ACCESSIBILITY_NAME");
        m.put(516, "KEYBINDING");
        m.put(517, "HEARTBEAT");
        m.put(518, "SB_NONBLOCKING");
        m.put(519, "LATENCY_CHECK");
        m.put(520, "DELETE_CHILDREN");
        m.put(521, "FOCUSLIST_REMOVE");
        m.put(522, "STBAR_REMOVE_LAMPS");
        m.put(523, "CTIME_MESSAGE");
        m.put(524, "CTIME_ENABLE");
        m.put(525, "NLS_LANG");
        m.put(526, "ASYNC_MESSAGE");
        m.put(527, "UPDATE_ASYNC_PROCESSING");
        m.put(528, "MAX_LENGTH_IS_BYTES");
        m.put(529, "DATETIME_LOCAL_TZ");
        m.put(530, "DEFAULT_LOCAL_TZ");
        m.put(531, "OK_TO_PASTE");
        m.put(532, "SELECTION_START");
        m.put(533, "SELECTION_END");
        m.put(534, "STOP_QUERY_LABEL");
        m.put(535, "RT_MSE_PRSD_NODE");
        m.put(536, "MONITOR");
        m.put(537, "ROWLOCK_REQUIRED");
        m.put(538, "WINSYS_RECORD_NAMES");
        m.put(539, "WINDOW_NAME");
        m.put(540, "MONITOR_START");
        m.put(541, "BLOCK_SCROLLER_ID");
        m.put(546, "JAVASCRIPT_EVENT");
        m.put(547, "JAVASCRIPT_EVENT_NAME");
        m.put(548, "JAVASCRIPT_EVENT_VALUE");
        m.put(549, "WINSYS_JS_EXPRESSION");
        m.put(550, "JAVASCRIPT_ENABLED");
        m.put(551, "MULTIBYTE_MNEMONIC");
        m.put(552, "JAVASCRIPT_BLOCKS_HEARTBEAT");
        m.put(553, "JAVASCRIPT_DONE");
        m.put(554, "JAVASCRIPT_RETURN_VALUE");
        m.put(555, "MOUSE_DOWN_MSG_SENT");
        m.put(556, "FOCUS_LOG");
        m.put(557, "FOCUS_WARNING");
        m.put(558, "MESSAGE_RUEI_BEGIN");
        m.put(559, "MESSAGE_RUEI_END");
        m.put(560, "CLIENT_IDLE_EXPIRED");
        m.put(561, "CLIENT_IDLE_DURATION");
        m.put(562, "MAX_EVENT_WAIT");
        m.put(563, "SSO_LOGOUT");
        m.put(564, "WEBSTART_SESSION");
        m.put(565, "STAND_ALONE_APP");
        m.put(566, "PLAY_AUDIO");
        m.put(567, "QUIET");
        m.put(568, "GRADIENT");
        m.put(569, "BACKGROUND_IMAGE_VALUE");
        m.put(570, "BACKGROUND_IMAGE_FIXED_SIZE");
    }

}
