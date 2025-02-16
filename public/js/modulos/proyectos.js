import Swal from 'sweetalert2';
import axios from 'axios';

const btnEliminar = document.querySelector('#eliminar-proyecto');

if(btnEliminar){
	btnEliminar.addEventListener('click', e => {
		
		//lo leo desde tareas.pug
		const urlProyecto = e.target.dataset.proyectoUrl;

		//console.log(urlProyecto);
		Swal.fire({
		  title: 'Deseas borrar este proyecto?',
		  text: "Un proyecto eliminado no se puede recuperar!",
		  icon: 'warning',
		  showCancelButton: true,
		  confirmButtonColor: '#3085d6',
		  cancelButtonColor: '#d33',
		  confirmButtonText: 'Sí, Borrar!',
		  cancelButtonText: 'No, Cancelar'
		}).then((result) => {
		  if (result.value) {
		  	//si es sí, enviamos petición eliminar a axios

		  	//leo la url a eliminar
		  	const url = `${location.origin}/proyectos/${urlProyecto}`;

		  	axios.delete(url, { params: {urlProyecto} })
		  		.then(function(respuesta){
		  			console.log(respuesta);
		  			Swal.fire(
					      'Proyecto Eliminado!',
					      respuesta.data,
					      'success'
					    );
					    // redireccionar al inicio
						setTimeout(() => {
							window.location.href = '/'
						}, 3000);	
		  		})
		  		.catch(() => {
		  			Swal.fire({
		  				type: 'error',
		  				title: 'Hubo un error',
		  				text: 'No se pudo eliminar el proyecto'
		  			})
		  		})
		  	}
		})
	})
}

export default btnEliminar;