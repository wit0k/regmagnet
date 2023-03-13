import logging
import plugins

from md.errors import *
from importlib import import_module
from pkgutil import iter_modules

logger = logging.getLogger('regmagnet')

class plugin_manager(object):

    MANDATORY_PLUGIN_FUNCTIONS = ["load_config", "ingest_config", "set_default_format_fields", "add_format_fields", "run"]

    def __init__(self, parser_obj):

        print(CYELLOW + '[+] Loading Plugin Manager' + CEND)
        self.parser = parser_obj
        self.plugins = {}
        logger.debug('Enumerating installed plugins')
        self.installed_plugins = self.get_installed_plugins()
        logger.debug("Found [%d] installed plugins" % len(self.installed_plugins))

    def load(self, plugin_name, plugin_params):

        plugin_name = plugin_name.lower()
        logger.debug('Loading plugin: "%s" -> Params: "%s"' % (plugin_name, plugin_params))
        print(CYELLOW + '[+] Loading Plugin: %s' % plugin_name + CEND)

        full_plugin_name = self.is_installed(plugin_name)

        if full_plugin_name:
            plugin_object = getattr(self.installed_plugins[full_plugin_name], plugin_name)

            """ Check IF mandatory functions are fulfilled """
            for _func in self.MANDATORY_PLUGIN_FUNCTIONS:
                if not getattr(plugin_object, _func, None):
                    logger.error("FAILED: Plugin: %s -> Msg: Function '%s' not found!" % (full_plugin_name, _func))
                    return False

            """ Check if a plugin supports currently loaded registry provider """
            # if not self.parser.reg.name in plugin_object.supported_providers:
            if not plugin_object.supported_providers:
                # Case: Plugin supports all providers
                pass
            elif not any(provider_name in plugin_object.supported_providers for provider_name in self.parser.provider.providers.keys()):
                logger.error('Plugin: %s -> Unsupported Registry Provider: %s' % (plugin_name, self.parser.reg.name))
                logger.error('Expected provider: "%s"' % plugin_object.supported_providers[0])
                return False

            logger.debug('Initialize the plugin object')

            from md.args import prepare_plugin_args
            plugin_params = prepare_plugin_args(plugin_params)

            # plugin_params = plugin_params.split(' ')

            #  Cosmetic issue fixed...
            if plugin_params == ['']:
                plugin_params = []

            plugin_object = plugin_object(params=plugin_params, parser=self.parser)

            if plugin_object:
                if not plugin_object.parser: plugin_object.parser = self.parser
                plugin_object.args = plugin_params
                """ Load the conf file (If there was any specified in the plugin code)"""
                if not plugin_object.load_config():
                    logger.error('Failed to load configuration for plugin: %s' % full_plugin_name)
                    return False
                else:
                    """ Add new format fields (If there were any specified in the conf file) """
                    plugin_object.add_format_fields()

                #  Ingest the config:
                plugin_object.ingest_config()

                logger.debug('Plugin: %s loaded successfully' % plugin_name)
                self.plugins[plugin_name] = {'full_plugin_name': full_plugin_name, "plugin_object": plugin_object}
                return True
            else:
                logger.error('Unable to initialize plugin object: %s' % plugin_name)
                return False
        else:
            logger.error(f"Plugin: '%s' is not installed!" % plugin_name)
            return False

    def is_installed(self, plugin_name):
        installed = None

        for _installed_plugin_name in self.installed_plugins.keys():
            try:
                _plugin_name = _installed_plugin_name[_installed_plugin_name.rindex(".") + 1:]
                if plugin_name == _plugin_name:
                    return _installed_plugin_name
            except ValueError:
                continue

        return installed

    def get_plugins(self):

        if self.plugins:
            return self.plugins

    def get_short_plugin_name(self, full_plugin_name):

        return full_plugin_name[full_plugin_name.rindex(".") + 1:]

    def get_installed_plugins(self):

        # Get the list of installed plugins
        installed_plugins = {
            name: import_module(name) for finder, name, ispkg in self._iter_namespace(plugins)
        }

        return installed_plugins

    def _iter_namespace(self, ns_pkg):
        # Specifying the second argument (prefix) to iter_modules makes the
        # returned name an absolute name instead of a relative one. This allows
        # import_module to work without having to do additional modification to
        # the name.
        return iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")

    def run(self, plugin, registry_hive, registry_handler=None, args=None, loaded_hives=None):

        logger.debug('Execute: %s -> Details: %s' % (plugin[0], plugin[1]))
        plugin_object = plugin[1].get('plugin_object', None)
        if plugin_object:
            if loaded_hives:
                plugin_object.loaded_hives = loaded_hives
                
            return plugin_object.run(hive=registry_hive, registry_handler=registry_handler, args=args)
        else:
            logger.error('The plugin: %s does not have the plugin_object initialized!' % plugin[0])
            return []


