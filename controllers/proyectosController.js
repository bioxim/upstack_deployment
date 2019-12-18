const Proyectos = require('../models/Proyectos');
const Tareas = require('../models/Tareas');

exports.proyectosHome = async (req, res) => {

		//console.log(res.locals.usuario);

		const usuarioId = res.locals.usuario.id;

		const proyectos = await Proyectos.findAll({where: {usuarioId}});

		res.render('index', {
			nombrePagina: 'Proyectos',
			proyectos
		});
}

exports.formularioProyecto = async (req, res) => {
		const usuarioId = res.locals.usuario.id;

		const proyectos = await Proyectos.findAll({where: {usuarioId}});

		res.render('nuevoProyecto', {
			nombrePagina: 'Nuevo Proyecto',
			proyectos
		});
}

// Para envío de datos desde el formulario
exports.nuevoProyecto = async (req, res) => {

		const usuarioId = res.locals.usuario.id;

		const proyectos = await Proyectos.findAll({where: {usuarioId}});

		// Enviar a la consola lo que el usuario escriba
		//console.log(req.body);
		// validar lo que tengamos en el input
		const nombre = req.body.nombre;

		let errores = [];

		if(!nombre) {
			errores.push({'texto': 'Agrega un nombre al proyecto'})
		}
		//Si hay errores:
		if(errores.length > 0) {
			res.render('nuevoProyecto', {
				nombrePagina : 'Nuevo Proyecto',
				errores,
				proyectos
			})
		} else {
			//no hay errores
			// insertar en la base de datos.
			const usuarioId = res.locals.usuario.id;
			await Proyectos.create({ nombre, usuarioId });
			res.redirect('/');
		}
}

exports.proyectoPorUrl = async (req, res, next) => {
	const usuarioId = res.locals.usuario.id;

	const proyectosPromise = Proyectos.findAll({where: {usuarioId}});

	const proyectoPromise = Proyectos.findOne({
		where: {
			url: req.params.url,
			usuarioId
		}
	});

	const [proyectos, proyecto] = await Promise.all([proyectosPromise, proyectoPromise]);

	// Consultar tareas del proyecto actual
	const tareas = await Tareas.findAll({
		where: {
			proyectoId: proyecto.id
		}//,
		//include: [
		//	{ model: Proyectos}
		//]
	});

	if (!proyecto) return next();
	//console.log(proyecto);
	// render a la vista
	res.render('tareas', {
		nombrePagina: 'Tareas del Proyecto',
		proyecto,
		proyectos,
		tareas
	});
}

exports.formularioEditar = async (req, res) => {

	const usuarioId = res.locals.usuario.id;

	const proyectosPromise = Proyectos.findAll({where: {usuarioId}});

	const proyectoPromise = Proyectos.findOne({
		where: {
			id: req.params.id,
			usuarioId
		}
	});

	const [proyectos, proyecto] = await Promise.all([proyectosPromise, proyectoPromise]);

	//render a la vista
	res.render('nuevoProyecto', {
		nombrePagina : 'Editar Proyecto',
		proyectos,
		proyecto
	})
}

exports.actualizarProyecto = async (req, res) => {

		const proyectos = await Proyectos.findAll();

		// Enviar a la consola lo que el usuario escriba
		//console.log(req.body);
		// validar lo que tengamos en el input
		const nombre = req.body.nombre;

		let errores = [];

		if(!nombre) {
			errores.push({'texto': 'Agrega un nombre al proyecto'})
		}
		//Si hay errores:
		if(errores.length > 0) {
			res.render('nuevoProyecto', {
				nombrePagina : 'Nuevo Proyecto',
				errores,
				proyectos
			})
		} else {
			//no hay errores
			// insertar en la base de datos.
			await Proyectos.update(
				{ nombre: nombre },
				{ where: {id: req.params.id }}
			);
			res.redirect('/');
		}
}

exports.eliminarProyecto = async (req, res, next) => {
	// para req, query o params(vamos a utilizar query)
	// console.log(req.query);
	const {urlProyecto} = req.query;

	const resultado = await Proyectos.destroy({where: { url : urlProyecto}});

	//si pasa algo con el servidor justo en el momento que le vas a dar eliminar
	if(!resultado) {
		return next();
	}

	res.status(200).send('Proyecto eliminado correctamente');
}