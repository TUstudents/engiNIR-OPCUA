# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
from importlib import metadata

project = "engiNIR-OPCUA"
copyright = "2015-2026, opcua-asyncio contributors; 2026, engiNIR-OPCUA contributors"
author = "opcua-asyncio and engiNIR-OPCUA contributors"
# release = "0.95.0"
version = metadata.version('enginir-opcua')

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    # "sphinx_copybutton",  # Currently not working with line numbers
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output
# https://pydata-sphinx-theme.readthedocs.io/en/latest/user_guide/index.html
html_theme = "pydata_sphinx_theme"
html_static_path = ["_static"]

html_theme_options = {
    "github_url": "https://github.com/TUstudents/engiNIR-OPCUA",
    "show_toc_level": 2, # Visible levels in the right navigation
    "show_nav_level": 2, # Default levels of expanded elements in the left navigation
}


# -- Options for sphinx.ext.autosectionlabel ---------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/autosectionlabel.html
autosectionlabel_prefix_document = True

# -- Options for sphinx.ext.intersphinx --------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/intersphinx.html
intersphinx_mapping = {'python': ('https://docs.python.org/3', None)}

# -- Options for sphinx.ext.todo ---------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/todo.html
todo_include_todos = True
