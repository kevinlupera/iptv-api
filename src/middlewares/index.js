const jwt = require("jsonwebtoken");
const API_KEY = process.env.API_KEY; // La API Key para validar las solicitudes
const SECRET_KEY = process.env.SECRET_KEY; // Clave secreta para JWT

// Middleware para validar la API Key
function validateApiKey(req, res, next) {
  const apiKey = req.headers["x-api-key"];
  if (apiKey === API_KEY) {
    next();
  } else {
    res.status(403).json({ error: "API Key inválida" });
  }
}
// Middleware para autenticar el token temporal (JWT)
function authenticateResetToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1]; // Obtener el token del header 'Authorization'

  if (!token) {
    return res
      .status(401)
      .json({ error: "Token requerido para restablecer la contraseña." });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err)
      return res.status(403).json({ error: "Token inválido o expirado." });

    req.userId = decoded.userId; // Almacenar el userId del token en la solicitud
    next();
  });
}

// Middleware para autenticar el token JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Middleware para verificar que el profile sea requerido
function requireProfile(req, res, next) {
  const profileId = req.query.profile || req.params.profileId;
  if (!profileId) {
    return res
      .status(400)
      .json({ error: 'El parámetro "profile" es requerido.' });
  }
  next();
}

module.exports = {requireProfile, authenticateToken, authenticateResetToken, validateApiKey};