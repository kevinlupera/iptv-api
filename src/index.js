require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const helmet = require("helmet");

const cors = require("cors");
const { body, validationResult } = require("express-validator");
const { validateApiKey, authenticateResetToken, authenticateToken, requireProfile } = require("./middlewares");
const {
  generateUniqueVerificationCode,
  generateToken,
  sendEmail,
  getFromApi,
  getProfileParams
} = require("./utils");
const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY; // Clave secreta para JWT
const saltRounds = 10; // Número de rondas de sal

app.use(express.json());
app.use(helmet());
app.use(cors());

// Conexión a MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Esquema de usuario y perfil
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  verificationToken: { type: String }, // Campo para el token de verificación
  verificationExpires: { type: Date }, // Campo para la fecha de expiración del token
  isVerified: { type: Boolean, default: false }, // Campo para verificar si la cuenta está activada
});

const profileSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  url: String,
  username: String,
  password: String,
  name: String,
});

const User = mongoose.model("User", userSchema);
const Profile = mongoose.model("Profile", profileSchema);

// Registro de usuario
app.post("/register", validateApiKey, async (req, res) => {
  const { username, password, email, firstName, lastName } = req.body;

  if (!username || !password || !email || !firstName || !lastName) {
    return res.status(400).json({ error: "Todos los campos son requeridos" });
  }

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser)
      return res.status(400).json({ error: "El usuario ya existe" });

    bcrypt.hash(password, saltRounds, async (err, hashedPassword) => {
      if (err) {
        console.error("Error al encriptar la contraseña:", err.message);
        return res
          .status(500)
          .json({ error: "Error al encriptar la contraseña" });
      }

      const verificationCode = await generateUniqueVerificationCode(User); // Generar un código único
      const expiresIn = new Date(Date.now() + 10 * 60 * 1000); // Caduca en 10 minutos

      const user = new User({
        username,
        password: hashedPassword,
        email,
        firstName,
        lastName,
        verificationToken: verificationCode, // Guardar el código de verificación
        verificationExpires: expiresIn, // Guardar la fecha de expiración
        isVerified: false,
      });

      await user.save();

      try {
        await sendEmail(
          email,
          { firstName, lastName, verificationCode },
          "verify"
        ); // Enviar el código de verificación de cuenta
        res.status(201).json({
          message:
            "Usuario registrado exitosamente. Por favor, verifica tu correo para activar tu cuenta.",
        });
      } catch (emailError) {
        await User.deleteOne({ email });
        res.status(500).json({
          error:
            "Error al enviar el correo de verificación. Tu cuenta no ha sido creada.",
        });
      }
    });
  } catch (error) {
    console.error("Error en el proceso de registro:", error.message);
    res.status(500).json({ error: "Error en el proceso de registro" });
  }
});

// Endpoint para verificar el código de verificación al crear una cuenta
app.post("/verify", validateApiKey, async (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res
      .status(400)
      .json({ error: "El código de verificación es requerido." });
  }

  try {
    // Buscar al usuario por el código de verificación
    const user = await User.findOne({ verificationToken: code });

    if (!user) {
      return res
        .status(400)
        .json({ error: "Código de verificación inválido." });
    }

    const now = new Date();
    if (user.verificationExpires && now > user.verificationExpires) {
      return res.status(400).json({
        error:
          "El código de verificación ha expirado. Por favor, solicita uno nuevo.",
      });
    }

    // Si es correcto, marcar la cuenta como verificada
    user.isVerified = true;
    user.verificationToken = null;
    user.verificationExpires = null;
    await user.save();

    // Enviar correo de felicitación por verificación de cuenta
    await sendEmail(
      user.email,
      {
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.username,
      },
      "congratulations"
    );

    res.status(200).json({
      message: "¡Cuenta verificada exitosamente! Ahora puedes iniciar sesión.",
    });
  } catch (error) {
    console.error("Error al verificar el código:", error.message);
    res.status(500).json({
      message: "Hubo un error al verificar la cuenta. Inténtalo de nuevo.",
    });
  }
});

// Ruta para reenviar el correo de verificación
app.post("/resend-verification", validateApiKey, async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res
      .status(400)
      .json({ error: "El correo electrónico es requerido." });
  }

  try {
    const user = await User.findOne({ email });

    if (!user) return res.status(404).json({ error: "Usuario no encontrado." });

    // Si la cuenta ya está verificada, no es necesario reenviar el código
    if (user.isVerified) {
      return res.status(400).json({ error: "La cuenta ya está verificada." });
    }

    // Generar un nuevo código de verificación y establecer una nueva fecha de expiración
    const newVerificationCode = await generateUniqueVerificationCode(User); // Generar un nuevo código de 6 dígitos
    const newExpirationTime = new Date(Date.now() + 10 * 60 * 1000); // Caduca en 10 minutos

    // Actualizar el código de verificación y su expiración en la base de datos
    user.verificationToken = newVerificationCode;
    user.verificationExpires = newExpirationTime;

    await user.save(); // Guardar los cambios

    // Enviar el nuevo correo de verificación con el código actualizado
    try {
      await sendEmail(
        user.email,
        {
          firstName: user.firstName,
          lastName: user.lastName,
          verificationCode: newVerificationCode,
        },
        "verify"
      );

      res
        .status(200)
        .json({ message: "Correo de verificación reenviado exitosamente." });
    } catch (emailError) {
      console.error("Error al enviar el correo de verificación:", emailError);
      res
        .status(500)
        .json({ error: "Error al enviar el correo de verificación." });
    }
  } catch (error) {
    console.error(
      "Error en el reenvío del correo de verificación:",
      error.message
    );
    res.status(500).json({ error: "Error al procesar la solicitud." });
  }
});

// Inicio de sesión
app.post(
  "/login",
  validateApiKey,
  body("username").notEmpty().withMessage("El nombre de usuario es requerido"),
  body("password").notEmpty().withMessage("La contraseña es requerida"),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    try {
      const user = await User.findOne({ username });

      // Verificar si el usuario existe
      if (!user) {
        return res.status(400).json({ error: "Credenciales inválidas" });
      }

      // Comparar la contraseña ingresada con el hash almacenado
      bcrypt.compare(password, user.password, (err, result) => {
        if (err)
          return res
            .status(500)
            .json({ error: "Error al comparar la contraseña" });

        // Si la contraseña es incorrecta
        if (!result)
          return res.status(400).json({ error: "Credenciales inválidas" });

        // Si la contraseña es correcta, verificar si la cuenta está verificada
        if (!user.isVerified) {
          return res.status(400).json({
            error:
              "Cuenta no verificada. Por favor, verifica tu cuenta antes de iniciar sesión.",
          });
        }

        // Generar y retornar el token si la cuenta está verificada
        const token = generateToken(user._id);
        res.json({ token });
      });
    } catch (error) {
      console.error("Error en el proceso de inicio de sesión:", error.message);
      res
        .status(500)
        .json({ error: "Error en el proceso de inicio de sesión" });
    }
  }
);

// Endpoint para solicitar un código de recuperación de contraseña
app.post("/forgot-password", validateApiKey, async (req, res) => {
  const { email } = req.body;

  // Verificar que el campo de correo electrónico esté presente
  if (!email) {
    return res
      .status(400)
      .json({ error: "El correo electrónico es requerido." });
  }

  try {
    // Buscar al usuario por el correo proporcionado
    const user = await User.findOne({ email });

    // Si no se encuentra el usuario, devolver un error
    if (!user) return res.status(404).json({ error: "Usuario no encontrado." });

    // Generar un nuevo código de verificación (que se usará para la recuperación de contraseña)
    const verificationCode = await generateUniqueVerificationCode(User); // Generar un nuevo código de 6 dígitos
    const expiresIn = new Date(Date.now() + 10 * 60 * 1000); // El código caduca en 10 minutos

    // Guardar el código de verificación y la fecha de expiración en el usuario
    user.verificationToken = verificationCode;
    user.verificationExpires = expiresIn;

    await user.save(); // Guardar los cambios en la base de datos

    // Enviar un correo con el código de recuperación al usuario
    try {
      await sendEmail(email, { verificationCode }, "recovery"); // Enviar el código de recuperación de contraseña
      res
        .status(200)
        .json({ message: "Código de recuperación enviado exitosamente." });
    } catch (emailError) {
      console.error("Error al enviar el correo de recuperación:", emailError);
      res
        .status(500)
        .json({ error: "Error al enviar el correo de recuperación." });
    }
  } catch (error) {
    console.error(
      "Error en el proceso de recuperación de contraseña:",
      error.message
    );
    res.status(500).json({ error: "Error al procesar la solicitud." });
  }
});

// Endpoint para verificar el código de verificación para restablecer la contraseña
app.post("/verify-reset-code", validateApiKey, async (req, res) => {
  const { verificationCode } = req.body;

  if (!verificationCode) {
    return res
      .status(400)
      .json({ error: "El código de verificación es requerido." });
  }

  try {
    // Buscar al usuario por el código de verificación
    const user = await User.findOne({ verificationToken: verificationCode });

    // Si no se encuentra el usuario, devolver un error
    if (!user)
      return res
        .status(404)
        .json({ error: "Código de verificación inválido." });

    // Verificar si el código ha expirado (comparar la fecha actual con la fecha de expiración)
    const now = new Date();
    if (now > user.verificationExpires) {
      return res.status(400).json({
        error:
          "El código de verificación ha expirado. Por favor, solicita uno nuevo.",
      });
    }

    // Generar un token temporal para la recuperación de contraseña (válido por 15 minutos)
    const resetToken = jwt.sign({ userId: user._id }, SECRET_KEY, {
      expiresIn: "15m",
    });

    // Enviar el token temporal al cliente
    res.status(200).json({
      message: "Código de verificación válido para restablecer tu contraseña.",
      resetToken: resetToken, // Este token será usado en la siguiente solicitud para cambiar la contraseña
    });
  } catch (error) {
    console.error("Error al verificar el código:", error.message);
    res.status(500).json({
      error: "Hubo un error al verificar el código. Inténtalo de nuevo.",
    });
  }
});

// Endpoint para restablecer la contraseña después de verificar el código
app.post(
  "/reset-password",
  validateApiKey,
  authenticateResetToken,
  async (req, res) => {
    const { newPassword } = req.body;

    if (!newPassword) {
      return res
        .status(400)
        .json({ error: "La nueva contraseña es requerida." });
    }

    try {
      // Buscar al usuario por el userId almacenado en el token temporal
      const user = await User.findById(req.userId);

      if (!user)
        return res.status(404).json({ error: "Usuario no encontrado." });

      // Verificar que no exista un token activo o que ya se haya utilizado
      if (!user.verificationToken) {
        return res.status(400).json({
          message: "Tu contraseña ya ha sido cambiada anteriormente.",
        });
      }

      // Encriptar la nueva contraseña
      bcrypt.hash(newPassword, saltRounds, async (err, hashedPassword) => {
        if (err) {
          console.error("Error al encriptar la nueva contraseña:", err.message);
          return res
            .status(500)
            .json({ error: "Error al encriptar la nueva contraseña." });
        }

        // Actualizar la contraseña en la base de datos
        user.password = hashedPassword;
        user.verificationToken = null; // Limpiar cualquier token existente
        user.verificationExpires = null; // Limpiar la expiración del token
        await user.save(); // Guardar los cambios

        // Enviar correo de confirmación de restablecimiento exitoso
        await sendEmail(
          user.email,
          {
            firstName: user.firstName,
            lastName: user.lastName,
          },
          "password-reset-success"
        );

        // Enviar una respuesta exitosa
        res
          .status(200)
          .json({ message: "¡Contraseña restablecida exitosamente!" });
      });
    } catch (error) {
      console.error("Error al restablecer la contraseña:", error.message);
      res.status(500).json({
        error:
          "Hubo un error al restablecer la contraseña. Inténtalo de nuevo.",
      });
    }
  }
);

// Endpoint para recuperar el nombre de usuario por correo electrónico
app.post("/recover-username", validateApiKey, async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res
      .status(400)
      .json({ error: "El correo electrónico es requerido." });
  }

  try {
    // Buscar al usuario por el correo proporcionado
    const user = await User.findOne({ email });

    if (!user) {
      return res
        .status(404)
        .json({ error: "No se encontró una cuenta asociada a ese correo." });
    }

    // Enviar el correo con el nombre de usuario
    await sendEmail(
      email,
      {
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.username,
      },
      "username-recovery"
    );

    res
      .status(200)
      .json({ message: "El nombre de usuario ha sido enviado a tu correo." });
  } catch (error) {
    console.error(
      "Error al enviar el correo de recuperación de nombre de usuario:",
      error.message
    );
    res.status(500).json({
      error: "Hubo un error al procesar tu solicitud. Inténtalo de nuevo.",
    });
  }
});

// ----------------------------------- Perfiles -----------------------------------

// Crear un perfil para el usuario autenticado
app.post(
  "/profiles",
  validateApiKey,
  authenticateToken,
  body("name").notEmpty().withMessage("El nombre es requerido"),
  body("url").notEmpty().withMessage("La URL es requerida"),
  body("username").notEmpty().withMessage("El nombre de usuario es requerido"),
  body("password").notEmpty().withMessage("La contraseña es requerida"),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { url, username, password, name } = req.body;

    try {
      // Verificar si ya existe un perfil con el mismo username para el usuario autenticado
      const existingProfile = await Profile.findOne({
        userId: req.user.userId,
        name,
      });
      if (existingProfile) {
        return res.status(400).json({
          error:
            "Ya existe un perfil con ese nombre de usuario para este usuario",
        });
      }

      // Crear un nuevo perfil
      const profile = new Profile({
        userId: req.user.userId,
        url,
        username,
        password,
        name,
      });
      await profile.save();
      res.status(201).json(profile);
    } catch (error) {
      console.error("Error al crear el perfil:", error);
      res.status(500).json({ error: "Error al crear el perfil" });
    }
  }
);

// Obtener todos los perfiles del usuario autenticado
app.get("/profiles", validateApiKey, authenticateToken, async (req, res) => {
  const profiles = await Profile.find({ userId: req.user.userId });
  res.json(profiles);
});

// Obtener un perfil específico del usuario autenticado
app.get(
  "/profiles/:profileId",
  validateApiKey,
  authenticateToken,
  async (req, res) => {
    const { profileId } = req.params;

    // Buscar el perfil especificado
    const profile = await Profile.findOne({
      _id: profileId,
      userId: req.user.userId,
    });

    if (!profile) {
      return res.status(404).json({ error: "Perfil no encontrado" });
    }

    res.json(profile);
  }
);

// ----------------------------------- VOD Endpoints -----------------------------------

// Endpoint para obtener VODs recientes
app.get(
  "/vods/recent",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      // Obtener el perfil asociado con la solicitud
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;

      // Obtener parámetros de consulta
      const page = parseInt(req.query.page) || 1;
      const limit = 10;
      const totalItems = 50; // Total de artículos que queremos obtener

      // Obtener todas las VODs de la API
      const vods = await getFromApi(url, username, password, "get_vod_streams");

      // Filtrar las VODs por fecha de agregado
      const recentVods = vods
        .sort((a, b) => parseInt(b.added) - parseInt(a.added)) // Ordenar por fecha de agregado
        .slice(0, totalItems); // Obtener solo las primeras 50 VODs

      // Aplicar paginación
      const paginatedVods = recentVods.slice((page - 1) * limit, page * limit);

      // Responder con la paginación y los datos
      res.json({
        page: page,
        total: recentVods.length,
        totalPages: Math.ceil(recentVods.length / limit),
        data: paginatedVods,
      });
    } catch (error) {
      // Manejo de errores
      console.error("Error al obtener los VODs recientes:", error.message);
      res.status(500).json({ error: "Error al obtener los VODs recientes" });
    }
  }
);

// Obtener todas las categorías de VODs
app.get(
  "/vods/categories",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;

      const categories = await getFromApi(
        url,
        username,
        password,
        "get_vod_categories"
      );

      res.json(categories);
    } catch (error) {
      console.error("Error al obtener las categorías de VODs:", error.message);
      res
        .status(500)
        .json({ error: "Error al obtener las categorías de VODs" });
    }
  }
);

// Obtener todos los VODs paginados
app.get(
  "/vods",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;
      const page = parseInt(req.query.page) || 1;
      const limit = 10;

      const vods = await getFromApi(url, username, password, "get_vod_streams");

      const paginatedVods = vods.slice((page - 1) * limit, page * limit);

      res.json({
        page: page,
        total: vods.length,
        totalPages: Math.ceil(vods.length / limit),
        data: paginatedVods,
      });
    } catch (error) {
      console.error("Error al obtener los VODs:", error.message);
      res.status(500).json({ error: "Error al obtener los VODs" });
    }
  }
);

// Obtener VODs por categoría con paginación
app.get(
  "/vods/category/:categoryId",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;
      const categoryId = req.params.categoryId;
      const page = parseInt(req.query.page) || 1;
      const limit = 10;

      const vods = await getFromApi(
        url,
        username,
        password,
        "get_vod_streams",
        `&category_id=${categoryId}`
      );

      const paginatedVods = vods.slice((page - 1) * limit, page * limit);

      res.json({
        page: page,
        total: vods.length,
        totalPages: Math.ceil(vods.length / limit),
        data: paginatedVods,
      });
    } catch (error) {
      console.error("Error al obtener los VODs por categoría:", error.message);
      res
        .status(500)
        .json({ error: "Error al obtener los VODs por categoría" });
    }
  }
);

// Obtener detalles de un VOD específico
app.get(
  "/vods/:vodId",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;
      const vodId = req.params.vodId;

      const vodDetail = await getFromApi(
        url,
        username,
        password,
        "get_vod_streams",
        `&vod_id=${vodId}`
      );

      res.json(vodDetail);
    } catch (error) {
      console.error("Error al obtener los detalles del VOD:", error.message);
      res.status(500).json({ error: "Error al obtener los detalles del VOD" });
    }
  }
);

// ----------------------------------- Series Endpoints -----------------------------------

// Endpoint para obtener series recientes
app.get(
  "/series/recent",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;
      const page = parseInt(req.query.page) || 1;
      const limit = 10;

      // Realizar la solicitud a la API IPTV para obtener las series
      const series = await getFromApi(url, username, password, "get_series");

      // Limitar la respuesta a las primeras 50 series
      const limitedSeries = series.slice(0, 50);

      // Ordenar las series por fecha agregada (campo "added") de más reciente a más antigua
      const sortedSeries = limitedSeries.sort(
        (a, b) => new Date(b.added) - new Date(a.added)
      );

      // Paginación de las series
      const paginatedSeries = sortedSeries.slice(
        (page - 1) * limit,
        page * limit
      );

      // Responder con los datos paginados
      res.json({
        page: page,
        total: limitedSeries.length, // Ahora será 50 como máximo
        totalPages: Math.ceil(limitedSeries.length / limit),
        data: paginatedSeries,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Error al obtener las series recientes" });
    }
  }
);

// Obtener todas las categorías de series
app.get(
  "/series/categories",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;

      const categories = await getFromApi(
        url,
        username,
        password,
        "get_series_categories"
      );

      res.json(categories);
    } catch (error) {
      console.error(
        "Error al obtener las categorías de series:",
        error.message
      );
      res
        .status(500)
        .json({ error: "Error al obtener las categorías de series" });
    }
  }
);

// Obtener todas las series paginadas
app.get(
  "/series",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;
      const page = parseInt(req.query.page) || 1;
      const limit = 10;

      const series = await getFromApi(url, username, password, "get_series");

      const paginatedSeries = series.slice((page - 1) * limit, page * limit);

      res.json({
        page: page,
        total: series.length,
        totalPages: Math.ceil(series.length / limit),
        data: paginatedSeries,
      });
    } catch (error) {
      console.error("Error al obtener las series:", error.message);
      res.status(500).json({ error: "Error al obtener las series" });
    }
  }
);

// Obtener series por categoría con paginación
app.get(
  "/series/category/:categoryId",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;
      const categoryId = req.params.categoryId;
      const page = parseInt(req.query.page) || 1;
      const limit = 10;

      const series = await getFromApi(
        url,
        username,
        password,
        "get_series_streams",
        `&category_id=${categoryId}`
      );

      const paginatedSeries = series.slice((page - 1) * limit, page * limit);

      res.json({
        page: page,
        total: series.length,
        totalPages: Math.ceil(series.length / limit),
        data: paginatedSeries,
      });
    } catch (error) {
      console.error(
        "Error al obtener las series por categoría:",
        error.message
      );
      res
        .status(500)
        .json({ error: "Error al obtener las series por categoría" });
    }
  }
);

// Obtener detalles de una serie específica
app.get(
  "/series/:seriesId",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;
      const seriesId = req.params.seriesId;

      const seriesDetail = await getFromApi(
        url,
        username,
        password,
        "get_series_streams",
        `&series_id=${seriesId}`
      );

      res.json(seriesDetail);
    } catch (error) {
      console.error(
        "Error al obtener los detalles de la serie:",
        error.message
      );
      res
        .status(500)
        .json({ error: "Error al obtener los detalles de la serie" });
    }
  }
);

// ----------------------------------- Live Streams Endpoints -----------------------------------

app.get(
  "/live/recent",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;
      const page = parseInt(req.query.page) || 1;
      const limit = 10;

      // Realizar la solicitud a la API IPTV para obtener los live streams
      const liveStreams = await getFromApi(
        url,
        username,
        password,
        "get_live_streams"
      );

      // Limitar la respuesta a los primeros 50 live streams
      const limitedLiveStreams = liveStreams.slice(0, 50);

      // Ordenar los live streams por fecha agregada (campo "added") de más reciente a más antiguo
      const sortedLiveStreams = limitedLiveStreams.sort(
        (a, b) => new Date(b.added) - new Date(a.added)
      );

      // Paginación de los live streams
      const paginatedLiveStreams = sortedLiveStreams.slice(
        (page - 1) * limit,
        page * limit
      );

      // Responder con los datos paginados
      res.json({
        page: page,
        total: limitedLiveStreams.length, // Ahora será 50 como máximo
        totalPages: Math.ceil(limitedLiveStreams.length / limit),
        data: paginatedLiveStreams,
      });
    } catch (error) {
      console.error(error);
      res
        .status(500)
        .json({ error: "Error al obtener los live streams recientes" });
    }
  }
);

// Obtener todas las categorías de live streams
app.get(
  "/live/categories",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;

      const categories = await getFromApi(
        url,
        username,
        password,
        "get_live_categories"
      );

      res.json(categories);
    } catch (error) {
      console.error(
        "Error al obtener las categorías de live streams:",
        error.message
      );
      res
        .status(500)
        .json({ error: "Error al obtener las categorías de live streams" });
    }
  }
);

// Obtener todos los live streams paginados
app.get(
  "/live",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;
      const page = parseInt(req.query.page) || 1;
      const limit = 10;

      const liveStreams = await getFromApi(
        url,
        username,
        password,
        "get_live_streams"
      );

      const paginatedLiveStreams = liveStreams.slice(
        (page - 1) * limit,
        page * limit
      );

      res.json({
        page: page,
        total: liveStreams.length,
        totalPages: Math.ceil(liveStreams.length / limit),
        data: paginatedLiveStreams,
      });
    } catch (error) {
      console.error("Error al obtener los live streams:", error.message);
      res.status(500).json({ error: "Error al obtener los live streams" });
    }
  }
);

// Obtener live streams por categoría con paginación
app.get(
  "/live/category/:categoryId",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;
      const categoryId = req.params.categoryId;
      const page = parseInt(req.query.page) || 1;
      const limit = 10;

      const liveStreams = await getFromApi(
        url,
        username,
        password,
        "get_live_streams",
        `&category_id=${categoryId}`
      );

      const paginatedLiveStreams = liveStreams.slice(
        (page - 1) * limit,
        page * limit
      );

      res.json({
        page: page,
        total: liveStreams.length,
        totalPages: Math.ceil(liveStreams.length / limit),
        data: paginatedLiveStreams,
      });
    } catch (error) {
      console.error(
        "Error al obtener los live streams por categoría:",
        error.message
      );
      res
        .status(500)
        .json({ error: "Error al obtener los live streams por categoría" });
    }
  }
);

// Obtener detalles de un live stream específico
app.get(
  "/live/:liveId",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile);
      const { url, username, password } = profile;
      const liveId = req.params.liveId;

      const liveStreamDetail = await getFromApi(
        url,
        username,
        password,
        "get_live_streams",
        `&live_id=${liveId}`
      );

      res.json(liveStreamDetail);
    } catch (error) {
      console.error(
        "Error al obtener los detalles del live stream:",
        error.message
      );
      res
        .status(500)
        .json({ error: "Error al obtener los detalles del live stream" });
    }
  }
);

// ----------------------------------- Search Streams Endpoints -----------------------------------

// Endpoint para realizar una búsqueda de series, películas y TV en vivo
app.get(
  "/search",
  validateApiKey,
  authenticateToken,
  requireProfile,
  async (req, res) => {
    try {
      const profile = await getProfileParams(req, Profile); // Obtener el perfil seleccionado
      const { url, username, password } = profile;
      const query = req.query.q;

      if (!query) {
        return res
          .status(400)
          .json({ error: "Debe proporcionar un término de búsqueda (q)" });
      }

      // Hacer solicitudes a la API IPTV para obtener resultados de TV en vivo, películas y series
      const [liveStreams, movies, series] = await Promise.all([
        getFromApi(url, username, password, "get_live_streams"),
        getFromApi(url, username, password, "get_vod_streams"),
        getFromApi(url, username, password, "get_series"),
      ]);

      // Filtrar los resultados por el término de búsqueda
      const filteredLiveStreams = liveStreams.filter((item) =>
        item.name.toLowerCase().includes(query.toLowerCase())
      );
      const filteredMovies = movies.filter((item) =>
        item.name.toLowerCase().includes(query.toLowerCase())
      );
      const filteredSeries = series.filter((item) =>
        item.name.toLowerCase().includes(query.toLowerCase())
      );

      res.json({
        query: query,
        liveStreams: filteredLiveStreams,
        movies: filteredMovies,
        series: filteredSeries,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Error al realizar la búsqueda" });
    }
  }
);

app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
