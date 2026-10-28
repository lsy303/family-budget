/* ═══════════════════════════════════════════════
   إعدادات Firebase + بيانات البائع
   انسخ القيم من: Firebase Console › Project settings › Your apps › Web app
   ═══════════════════════════════════════════════ */
var FIREBASE_CONFIG = {
  apiKey:            "PASTE_API_KEY",
  authDomain:        "PASTE_PROJECT_ID.firebaseapp.com",
  projectId:         "PASTE_PROJECT_ID",
  storageBucket:     "PASTE_PROJECT_ID.appspot.com",
  messagingSenderId: "PASTE_SENDER_ID",
  appId:             "PASTE_APP_ID"
};

var APP_SETTINGS = {
  // "off"      = يعمل محلياً بدون تسجيل دخول أو ترخيص (النسخة الحالية)
  // "firebase" = وضع البيع: تسجيل دخول + ترخيص — غيّرها بعد تعبئة FIREBASE_CONFIG أعلاه
  licenseMode:  "off",
  // بريد المدير (نفس البريد المكتوب في firestore.rules)
  adminEmail:   "PASTE_ADMIN_EMAIL",
  // رقم واتساب للشراء والتجديد — بالصيغة الدولية بدون + (مثال: 97333000000)
  whatsapp:     "97300000000",
  // رابط التطبيق المنشور (يظهر في رسالة التسليم للعميل)
  appUrl:       "https://lsy303.github.io/family-budget/",
  // مدة السماح بدون إنترنت (بالأيام)
  offlineDays:  30,
  // القيم الافتراضية عند إضافة عميل جديد
  defaultMonths:  12,
  defaultDevices: 2
};
