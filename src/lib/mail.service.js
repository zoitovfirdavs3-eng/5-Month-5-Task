require("dotenv").config();
const nodemailer = require("nodemailer");

const emailService = async (email, otp) => {
  const transport = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.SMTP_EMAIL,
      pass: process.env.SMTP_PASS,
    },
  });

  const html = `<!doctype html>
<html lang="uz">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>OTP tasdiqlash kodi</title>
</head>
<body style="margin:0;padding:0;background:#f6f7fb;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f6f7fb;padding:24px 0;">
    <tr>
      <td align="center">
        <table role="presentation" width="560" cellspacing="0" cellpadding="0" style="background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 6px 18px rgba(0,0,0,0.06);">
          <tr>
            <td style="padding:22px 24px;background:linear-gradient(135deg,#3b82f6,#06b6d4);color:#fff;">
              <div style="font-size:18px;font-weight:700;">OTP tasdiqlash kodi</div>
              <div style="font-size:13px;opacity:.9;margin-top:6px;">
                Hisobingiz xavfsizligi uchun kodni hech kimga bermang.
              </div>
            </td>
          </tr>

          <tr>
            <td style="padding:24px;">
              <div style="font-size:14px;color:#111827;line-height:1.6;">
                Salom! Ro‘yxatdan o‘tish (yoki login) jarayonini yakunlash uchun quyidagi tasdiqlash kodidan foydalaning:
              </div>

              <div style="margin:18px 0;padding:18px 16px;border:1px dashed #c7d2fe;border-radius:12px;background:#eef2ff;text-align:center;">
                <div style="font-size:12px;color:#4b5563;letter-spacing:.4px;">SIZNING OTP KODINGIZ</div>
                <div style="font-size:34px;font-weight:800;color:#111827;letter-spacing:6px;margin-top:6px;">
                  ${otp}
                </div>
              </div>

              <div style="font-size:13px;color:#374151;line-height:1.6;">
                ⏳ Ushbu kod <b>faqat 2 daqiqa</b> amal qiladi.
              </div>

              <div style="margin-top:14px;font-size:12px;color:#6b7280;line-height:1.6;">
                Agar siz bu so‘rovni yubormagan bo‘lsangiz, bu xabarni e’tiborsiz qoldiring.
              </div>
            </td>
          </tr>

          <tr>
            <td style="padding:16px 24px;background:#f9fafb;border-top:1px solid #e5e7eb;">
              <div style="font-size:12px;color:#6b7280;">
                © ${new Date().getFullYear()} Kutubxona. Barcha huquqlar himoyalangan.
              </div>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

  await transport.sendMail({
    from: `"Kutubxona" <${process.env.SMTP_EMAIL}>`,
    to: email,
    subject: "Stadium project: library email verify",
    html: html,
    text: `OTP: ${otp}. Ushbu kod faqat 2 daqiqa amal qiladi.`,
  });
};

module.exports = emailService;