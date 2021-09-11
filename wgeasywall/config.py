import typer
import wgeasywall.cmd.config.generate as generate
import wgeasywall.cmd.config.view as view

app = typer.Typer()

app.add_typer(generate.app,name="generate",help="WGeasywall components configuration generators")
app.add_typer(view.app,name="view",help="View WGeasywall components configurations")