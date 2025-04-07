package routes

import (
	"labgestor-server/internal/controllers"
	"labgestor-server/internal/repository"
	"labgestor-server/middleware"

	"github.com/labstack/echo/v4"
)

func NewUsuarioHanlder(e *echo.Echo, controller controllers.UsuarioController, repo repository.UsuarioRepository) {
	// -----------------------------------
	// Rutas Publicas
	// -----------------------------------
	e.POST("/login", controller.Login)
	e.POST("/actualizarContrasena", controller.CambiarContrasena)

	// -----------------------------------
	// Rutas Privadas
	// -----------------------------------
	e.POST("/logout", controller.Logout)
	e.POST("/registrarUsuario", controller.RegistrarUsuario)
	e.GET("/usuarios/:id", controller.ObtenerPerfil, middleware.RequireAuth(repo, "admin"))
	e.GET("/usuarios", controller.ObtenerUsuarios, middleware.RequireAuth(repo, "admin"))
}
