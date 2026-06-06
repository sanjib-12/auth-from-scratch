import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
   host: process.env.SMTP_HOST,
   port: Number(process.env.SMTP_PORT ?? 587),
   secure: false,
   auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
   }
});

export async function sendOtpEmail(to: string, code: string): Promise <void> {
   await transporter.sendMail({
      from: process.env.SMTP_FROM ?? process.env.SMTP_USER,
      to,
      subject: "Your login verification code",
      text:`Your verification code is : ${code} \n\n This code expires in 10 minutes. Do not share it with anyone.`,
   });
}