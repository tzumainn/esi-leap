#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import alembic
from alembic import config as alembic_config
import alembic.migration as alembic_migration

from esi_leap.db.sqlalchemy import models

import os
from oslo_db.sqlalchemy import enginefacade
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


def _alembic_config():
    path = os.path.join(os.path.dirname(__file__), "alembic.ini")
    config = alembic_config.Config(path)
    return config


def version(config=None, engine=None):
    """Current database version.

    :returns: Database version
    :rtype: string
    """
    if engine is None:
        engine = enginefacade.writer.get_engine()
    with engine.connect() as conn:
        context = alembic_migration.MigrationContext.configure(conn)
        return context.get_current_revision()


def upgrade(revision, config=None):
    """Used for upgrading database.

    :param version: Desired database version
    :type version: string
    """
    revision = revision or "head"
    config = config or _alembic_config()

    alembic.command.upgrade(config, revision or "head")


def downgrade(revision, config=None):
    """Used for downgrading database.

    :param version: Desired database version
    :type version: string
    """
    revision = revision or "base"
    config = config or _alembic_config()
    return alembic.command.downgrade(config, revision)


def stamp(revision, config=None):
    """Stamps database with provided revision.

    Don't run any migrations.

    :param revision: Should match one from repository or head - to stamp
                     database with most recent revision
    :type revision: string
    """
    config = config or _alembic_config()
    return alembic.command.stamp(config, revision=revision)


def revision(message=None, autogenerate=False, config=None):
    """Creates template for migration.

    :param message: Text that will be used for migration title
    :type message: string
    :param autogenerate: If True - generates diff based on current database
                         state
    :type autogenerate: bool
    """
    config = config or _alembic_config()
    return alembic.command.revision(config, message=message, autogenerate=autogenerate)


def create_schema(config=None, engine=None):
    """Create database schema from models description.

    Can be used for initial installation instead of upgrade('head').
    """
    if engine is None:
        engine = enginefacade.writer.get_engine()
    models.Base.metadata.create_all(engine)
    stamp("head", config=config)
