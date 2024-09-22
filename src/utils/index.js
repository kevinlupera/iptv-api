const jwt = require("jsonwebtoken");
const axios = require("axios");
const sgMail = require("@sendgrid/mail"); // Importar el paquete de SendGrid

const SECRET_KEY = process.env.SECRET_KEY; // Clave secreta para JWT
sgMail.setApiKey(process.env.SENDGRID_API_KEY); // Configurar la API Key de SendGrid desde las variables de entorno

// Función para generar un token JWT
export function generateToken(userId) {
  return jwt.sign({ userId }, SECRET_KEY, { expiresIn: "1h" });
}

// Función para obtener parámetros comunes de la solicitud
export async function getProfileParams(req, Profile) {
  const profileId = req.query.profile || req.params.profileId;
  const profile = await Profile.findOne({
    _id: profileId,
    userId: req.user.userId,
  });
  if (!profile) {
    throw new Error("Perfil no encontrado o no autorizado");
  }
  return profile;
}

// Función general para hacer solicitudes a la API IPTV
export async function getFromApi(
  apiUrl,
  username,
  password,
  action,
  additionalParams = ""
) {
  try {
    const response = await axios.get(
      `${apiUrl}/player_api.php?username=${username}&password=${password}&action=${action}${additionalParams}`
    );
    return response.data;
  } catch (error) {
    console.error("Error al hacer la solicitud a la API IPTV:", error);
    throw new Error("Error al comunicarse con la API IPTV");
  }
}

// ----------------------------------- Registro -----------------------------------

// Función para generar un código de verificación de 6 dígitos único
export async function generateUniqueVerificationCode(User) {
  let code;
  let userWithSameCode;

  do {
    code = Math.floor(100000 + Math.random() * 900000).toString(); // Genera un número de 6 dígitos
    userWithSameCode = await User.findOne({ verificationToken: code });
  } while (userWithSameCode); // Si el código ya está en uso, generar uno nuevo

  return code;
}

export async function sendEmail(to, content, messageType = "verify") {
  // Definir el asunto y el contenido del correo según el tipo de mensaje
  let subject, messageContent;

  if (messageType === "recovery") {
    subject = "Recuperación de contraseña";
    messageContent = `<p>Has solicitado restablecer tu contraseña. Usa el siguiente código para restablecerla: <strong>${content.verificationCode}</strong></p>`;
  } else if (messageType === "verify") {
    subject = "¡Bienvenido a nuestra plataforma! Verifica tu cuenta";
    messageContent = `<p>Hola ${content.firstName} ${content.lastName},</p>
                        <p>Gracias por unirte a nuestra comunidad. Estamos emocionados de tenerte a bordo.</p>
                        <p>Para completar tu registro, por favor introduce el siguiente código de verificación para activar tu cuenta: <strong>${content.verificationCode}</strong></p>
                        <p>Este paso es importante para proteger tu cuenta y asegurarnos de que puedas disfrutar de todas nuestras funciones.</p>
                        <p>Si tienes alguna pregunta o necesitas asistencia, no dudes en contactarnos.</p>
                        <p>¡Nos alegra que hayas decidido formar parte de nuestra plataforma!</p>`;
  } else if (messageType === "congratulations") {
    subject = "¡Felicitaciones! Tu cuenta ha sido verificada";
    messageContent = `<p>Hola ${content.firstName} ${content.lastName},</p>
                        <p>¡Felicitaciones! Tu cuenta ha sido verificada exitosamente en nuestra plataforma.</p>
                        <p>Tu nombre de usuario es: <strong>${content.username}</strong></p>
                        <p>Nos alegra que formes parte de nuestra comunidad. Si tienes alguna pregunta, no dudes en contactarnos.</p>
                        <p>¡Gracias por elegirnos!</p>`;
  } else if (messageType === "username-recovery") {
    subject = "Recuperación de tu nombre de usuario";
    messageContent = `<p>Hola ${content.firstName} ${content.lastName},</p>
                        <p>Recibimos una solicitud para recordarte tu nombre de usuario en nuestra plataforma.</p>
                        <p>Tu nombre de usuario es: <strong>${content.username}</strong></p>`;
  } else if (messageType === "password-reset-success") {
    subject = "Tu contraseña ha sido restablecida exitosamente";
    messageContent = `<p>Hola ${content.firstName} ${content.lastName},</p>
                        <p>¡Nos alegra informarte que tu contraseña ha sido restablecida exitosamente!</p>
                        <p>Si no solicitaste este cambio, por favor contáctanos de inmediato para proteger tu cuenta.</p>
                        <p>Tu seguridad es nuestra prioridad. Si necesitas ayuda adicional, no dudes en escribirnos.</p>
                        <p>¡Gracias por confiar en nosotros!</p>`;
  }

  const msg = {
    to: to,
    from: process.env.SENDGRID_FROM_EMAIL, // Dirección de correo verificada en SendGrid
    subject: subject,
    text: `Mensaje: ${messageContent}`, // Versión de texto plano
    html: `
          <div style="font-family: Arial, sans-serif; font-size: 16px; color: #333;">
              ${messageContent}
              <p>Mantenen tu cuenta segura.</p>
              <p>El equipo de TevePlay</p>
              <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
          </div>
      `,
  };

  try {
    await sgMail.send(msg); // Enviar el correo usando SendGrid
    console.log("Correo enviado exitosamente");
  } catch (error) {
    console.error("Error al enviar el correo:", error);
    throw new Error("Error al enviar el correo");
  }
}
