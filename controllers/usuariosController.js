const Usuarios = require('../models/Usuarios');
const enviarEmail = require('../handlers/email');

exports.formCrearCuenta = (req, res) => {
	res.render('crearCuenta', {
		nombrePagina : 'Crear Cuenta en Uptask'
	})
}

exports.formIniciarSesion = (req, res) => {
	const {error} = res.locals.mensajes;
	res.render('iniciarSesion', {
		nombrePagina : 'Iniciar Sesión en Uptask',
		error
	})
}

exports.crearCuenta = async (req, res) => {
	// leer los datos
	//console.log(req.body);
	const { email, password } = req.body;

	try {
		//Crea el usuario
		await Usuarios.create({
			email,
			password
		});
		//Crear URL de confirmar
		const confirmarUrl = `http://${req.headers.host}/confirmar/${email}`;

		// Crear el objeto de usuario
		const usuario = {
			email
		}

		// enviar email
		await enviarEmail.enviar({
	        usuario,
	        subject: 'Confirma tu cuenta UpTask',
	        confirmarUrl,
	        archivo: 'confirmar-cuenta'
	    });

		// redirigir al usuario
		req.flash('correcto', 'Enviamos un correo, confirma tu cuenta');
		res.redirect('/iniciar-sesion');
	} catch(error) {
		req.flash('error', error.errors.map(error => error.message));
		res.render('crearCuenta', {
			mensajes: req.flash(),
			nombrePagina: 'Crear Cuenta en Uptask',
			email,
			password
		})
	}
}

exports.formReestablecerPassword = (req, res) => {
	res.render('reestablecer', {
		nombrePagina: 'Reestablecer tu Contraseña'
	})
}

// Cambia el estado de una cuenta
exports.confirmarCuenta = async (req, res) => {
	//res.json(req.params.correo);
	const usuario = await Usuarios.findOne({
		where: {
			email: req.params.correo
		}
	});

	// Si no existe el usuario
	if(!usuario) {
		req.flash('error', 'No Válido');
		res.redirect('/crear-cuenta');
	}

	usuario.activo = 1;
	await usuario.save();

	req.flash('correcto', 'Cuenta activada correctamente');
	res.redirect('/iniciar-sesion');
}