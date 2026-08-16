/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2003 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

#include "sm.h"

/** @file sm/mod_template_roster.c
  * @brief user auto-population - roster
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.11 $
  */

/* user template - roster */

typedef struct _template_roster_st {
    sm_t       sm;
    const char *filename;
    time_t     mtime;
    xht        items;
} *template_roster_t;


static void _template_roster_free(module_t mod) {
    template_roster_t tr = (template_roster_t) mod->private;

    if(tr->items != NULL)
        xhash_free(tr->items);

    free(tr);
}

int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;
    const char *filename;
    template_roster_t tr;

    if(mod->init) return 0;

    filename = config_get_one(mod->mm->sm->config, "user.template.roster", 0);
    if(filename == NULL)
        return 0;

    tr = (template_roster_t) calloc(1, sizeof(struct _template_roster_st));

    tr->sm = mod->mm->sm;
    tr->filename = filename;

    mod->private = tr;

    mod->free = _template_roster_free;

    return 0;
}
