from jinja2 import Environment, FileSystemLoader, select_autoescape

def render_email(template_dir: str, template_name: str, context: dict) -> str:
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"])
    )
    tpl = env.get_template(template_name)
    return tpl.render(**context)
