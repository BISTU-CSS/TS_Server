// This file was generated by ODB, object-relational mapping (ORM)
// compiler for C++.
//

#include <odb/pre.hxx>

#include "system_info-odb.hxx"

#include <cassert>
#include <cstring>  // std::memcpy


#include <odb/mysql/traits.hxx>
#include <odb/mysql/database.hxx>
#include <odb/mysql/transaction.hxx>
#include <odb/mysql/connection.hxx>
#include <odb/mysql/statement.hxx>
#include <odb/mysql/statement-cache.hxx>
#include <odb/mysql/simple-object-statements.hxx>
#include <odb/mysql/container-statements.hxx>
#include <odb/mysql/exceptions.hxx>
#include <odb/mysql/simple-object-result.hxx>
#include <odb/mysql/enum.hxx>

namespace odb
{
  // system_info
  //

  struct access::object_traits_impl< ::system_info, id_mysql >::extra_statement_cache_type
  {
    extra_statement_cache_type (
      mysql::connection&,
      image_type&,
      id_image_type&,
      mysql::binding&,
      mysql::binding&)
    {
    }
  };

  access::object_traits_impl< ::system_info, id_mysql >::id_type
  access::object_traits_impl< ::system_info, id_mysql >::
  id (const image_type& i)
  {
    mysql::database* db (0);
    ODB_POTENTIALLY_UNUSED (db);

    id_type id;
    {
      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_value (
        id,
        i.conf_key_value,
        i.conf_key_size,
        i.conf_key_null);
    }

    return id;
  }

  bool access::object_traits_impl< ::system_info, id_mysql >::
  grow (image_type& i,
        my_bool* t)
  {
    ODB_POTENTIALLY_UNUSED (i);
    ODB_POTENTIALLY_UNUSED (t);

    bool grew (false);

    // conf_key_
    //
    if (t[0UL])
    {
      i.conf_key_value.capacity (i.conf_key_size);
      grew = true;
    }

    // conf_value_
    //
    if (t[1UL])
    {
      i.conf_value_value.capacity (i.conf_value_size);
      grew = true;
    }

    return grew;
  }

  void access::object_traits_impl< ::system_info, id_mysql >::
  bind (MYSQL_BIND* b,
        image_type& i,
        mysql::statement_kind sk)
  {
    ODB_POTENTIALLY_UNUSED (sk);

    using namespace mysql;

    std::size_t n (0);

    // conf_key_
    //
    if (sk != statement_update)
    {
      b[n].buffer_type = MYSQL_TYPE_STRING;
      b[n].buffer = i.conf_key_value.data ();
      b[n].buffer_length = static_cast<unsigned long> (
        i.conf_key_value.capacity ());
      b[n].length = &i.conf_key_size;
      b[n].is_null = &i.conf_key_null;
      n++;
    }

    // conf_value_
    //
    b[n].buffer_type = MYSQL_TYPE_STRING;
    b[n].buffer = i.conf_value_value.data ();
    b[n].buffer_length = static_cast<unsigned long> (
      i.conf_value_value.capacity ());
    b[n].length = &i.conf_value_size;
    b[n].is_null = &i.conf_value_null;
    n++;
  }

  void access::object_traits_impl< ::system_info, id_mysql >::
  bind (MYSQL_BIND* b, id_image_type& i)
  {
    std::size_t n (0);
    b[n].buffer_type = MYSQL_TYPE_STRING;
    b[n].buffer = i.id_value.data ();
    b[n].buffer_length = static_cast<unsigned long> (
      i.id_value.capacity ());
    b[n].length = &i.id_size;
    b[n].is_null = &i.id_null;
  }

  bool access::object_traits_impl< ::system_info, id_mysql >::
  init (image_type& i,
        const object_type& o,
        mysql::statement_kind sk)
  {
    ODB_POTENTIALLY_UNUSED (i);
    ODB_POTENTIALLY_UNUSED (o);
    ODB_POTENTIALLY_UNUSED (sk);

    using namespace mysql;

    bool grew (false);

    // conf_key_
    //
    if (sk == statement_insert)
    {
      ::std::string const& v =
        o.conf_key_;

      bool is_null (false);
      std::size_t size (0);
      std::size_t cap (i.conf_key_value.capacity ());
      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_image (
        i.conf_key_value,
        size,
        is_null,
        v);
      i.conf_key_null = is_null;
      i.conf_key_size = static_cast<unsigned long> (size);
      grew = grew || (cap != i.conf_key_value.capacity ());
    }

    // conf_value_
    //
    {
      ::std::string const& v =
        o.conf_value_;

      bool is_null (false);
      std::size_t size (0);
      std::size_t cap (i.conf_value_value.capacity ());
      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_image (
        i.conf_value_value,
        size,
        is_null,
        v);
      i.conf_value_null = is_null;
      i.conf_value_size = static_cast<unsigned long> (size);
      grew = grew || (cap != i.conf_value_value.capacity ());
    }

    return grew;
  }

  void access::object_traits_impl< ::system_info, id_mysql >::
  init (object_type& o,
        const image_type& i,
        database* db)
  {
    ODB_POTENTIALLY_UNUSED (o);
    ODB_POTENTIALLY_UNUSED (i);
    ODB_POTENTIALLY_UNUSED (db);

    // conf_key_
    //
    {
      ::std::string& v =
        o.conf_key_;

      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_value (
        v,
        i.conf_key_value,
        i.conf_key_size,
        i.conf_key_null);
    }

    // conf_value_
    //
    {
      ::std::string& v =
        o.conf_value_;

      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_value (
        v,
        i.conf_value_value,
        i.conf_value_size,
        i.conf_value_null);
    }
  }

  void access::object_traits_impl< ::system_info, id_mysql >::
  init (id_image_type& i, const id_type& id)
  {
    bool grew (false);
    {
      bool is_null (false);
      std::size_t size (0);
      std::size_t cap (i.id_value.capacity ());
      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_image (
        i.id_value,
        size,
        is_null,
        id);
      i.id_null = is_null;
      i.id_size = static_cast<unsigned long> (size);
      grew = grew || (cap != i.id_value.capacity ());
    }

    if (grew)
      i.version++;
  }

  const char access::object_traits_impl< ::system_info, id_mysql >::persist_statement[] =
  "INSERT INTO `system_info` "
  "(`conf_key`, "
  "`conf_value`) "
  "VALUES "
  "(?, ?)";

  const char access::object_traits_impl< ::system_info, id_mysql >::find_statement[] =
  "SELECT "
  "`system_info`.`conf_key`, "
  "`system_info`.`conf_value` "
  "FROM `system_info` "
  "WHERE `system_info`.`conf_key`=?";

  const char access::object_traits_impl< ::system_info, id_mysql >::update_statement[] =
  "UPDATE `system_info` "
  "SET "
  "`conf_value`=? "
  "WHERE `conf_key`=?";

  const char access::object_traits_impl< ::system_info, id_mysql >::erase_statement[] =
  "DELETE FROM `system_info` "
  "WHERE `conf_key`=?";

  const char access::object_traits_impl< ::system_info, id_mysql >::query_statement[] =
  "SELECT "
  "`system_info`.`conf_key`, "
  "`system_info`.`conf_value` "
  "FROM `system_info`";

  const char access::object_traits_impl< ::system_info, id_mysql >::erase_query_statement[] =
  "DELETE FROM `system_info`";

  const char access::object_traits_impl< ::system_info, id_mysql >::table_name[] =
  "`system_info`";

  void access::object_traits_impl< ::system_info, id_mysql >::
  persist (database& db, const object_type& obj)
  {
    ODB_POTENTIALLY_UNUSED (db);

    using namespace mysql;

    mysql::connection& conn (
      mysql::transaction::current ().connection ());
    statements_type& sts (
      conn.statement_cache ().find_object<object_type> ());

    callback (db,
              obj,
              callback_event::pre_persist);

    image_type& im (sts.image ());
    binding& imb (sts.insert_image_binding ());

    if (init (im, obj, statement_insert))
      im.version++;

    if (im.version != sts.insert_image_version () ||
        imb.version == 0)
    {
      bind (imb.bind, im, statement_insert);
      sts.insert_image_version (im.version);
      imb.version++;
    }

    insert_statement& st (sts.persist_statement ());
    if (!st.execute ())
      throw object_already_persistent ();

    callback (db,
              obj,
              callback_event::post_persist);
  }

  void access::object_traits_impl< ::system_info, id_mysql >::
  update (database& db, const object_type& obj)
  {
    ODB_POTENTIALLY_UNUSED (db);

    using namespace mysql;
    using mysql::update_statement;

    callback (db, obj, callback_event::pre_update);

    mysql::transaction& tr (mysql::transaction::current ());
    mysql::connection& conn (tr.connection ());
    statements_type& sts (
      conn.statement_cache ().find_object<object_type> ());

    const id_type& id (
      obj.conf_key_);
    id_image_type& idi (sts.id_image ());
    init (idi, id);

    image_type& im (sts.image ());
    if (init (im, obj, statement_update))
      im.version++;

    bool u (false);
    binding& imb (sts.update_image_binding ());
    if (im.version != sts.update_image_version () ||
        imb.version == 0)
    {
      bind (imb.bind, im, statement_update);
      sts.update_image_version (im.version);
      imb.version++;
      u = true;
    }

    binding& idb (sts.id_image_binding ());
    if (idi.version != sts.update_id_image_version () ||
        idb.version == 0)
    {
      if (idi.version != sts.id_image_version () ||
          idb.version == 0)
      {
        bind (idb.bind, idi);
        sts.id_image_version (idi.version);
        idb.version++;
      }

      sts.update_id_image_version (idi.version);

      if (!u)
        imb.version++;
    }

    update_statement& st (sts.update_statement ());
    if (st.execute () == 0)
      throw object_not_persistent ();

    callback (db, obj, callback_event::post_update);
    pointer_cache_traits::update (db, obj);
  }

  void access::object_traits_impl< ::system_info, id_mysql >::
  erase (database& db, const id_type& id)
  {
    using namespace mysql;

    ODB_POTENTIALLY_UNUSED (db);

    mysql::connection& conn (
      mysql::transaction::current ().connection ());
    statements_type& sts (
      conn.statement_cache ().find_object<object_type> ());

    id_image_type& i (sts.id_image ());
    init (i, id);

    binding& idb (sts.id_image_binding ());
    if (i.version != sts.id_image_version () || idb.version == 0)
    {
      bind (idb.bind, i);
      sts.id_image_version (i.version);
      idb.version++;
    }

    if (sts.erase_statement ().execute () != 1)
      throw object_not_persistent ();

    pointer_cache_traits::erase (db, id);
  }

  access::object_traits_impl< ::system_info, id_mysql >::pointer_type
  access::object_traits_impl< ::system_info, id_mysql >::
  find (database& db, const id_type& id)
  {
    using namespace mysql;

    {
      pointer_type p (pointer_cache_traits::find (db, id));

      if (!pointer_traits::null_ptr (p))
        return p;
    }

    mysql::connection& conn (
      mysql::transaction::current ().connection ());
    statements_type& sts (
      conn.statement_cache ().find_object<object_type> ());

    statements_type::auto_lock l (sts);

    if (l.locked ())
    {
      if (!find_ (sts, &id))
        return pointer_type ();
    }

    pointer_type p (
      access::object_factory<object_type, pointer_type>::create ());
    pointer_traits::guard pg (p);

    pointer_cache_traits::insert_guard ig (
      pointer_cache_traits::insert (db, id, p));

    object_type& obj (pointer_traits::get_ref (p));

    if (l.locked ())
    {
      select_statement& st (sts.find_statement ());
      ODB_POTENTIALLY_UNUSED (st);

      callback (db, obj, callback_event::pre_load);
      init (obj, sts.image (), &db);
      load_ (sts, obj, false);
      sts.load_delayed (0);
      l.unlock ();
      callback (db, obj, callback_event::post_load);
      pointer_cache_traits::load (ig.position ());
    }
    else
      sts.delay_load (id, obj, ig.position ());

    ig.release ();
    pg.release ();
    return p;
  }

  bool access::object_traits_impl< ::system_info, id_mysql >::
  find (database& db, const id_type& id, object_type& obj)
  {
    using namespace mysql;

    mysql::connection& conn (
      mysql::transaction::current ().connection ());
    statements_type& sts (
      conn.statement_cache ().find_object<object_type> ());

    statements_type::auto_lock l (sts);

    if (!find_ (sts, &id))
      return false;

    select_statement& st (sts.find_statement ());
    ODB_POTENTIALLY_UNUSED (st);

    reference_cache_traits::position_type pos (
      reference_cache_traits::insert (db, id, obj));
    reference_cache_traits::insert_guard ig (pos);

    callback (db, obj, callback_event::pre_load);
    init (obj, sts.image (), &db);
    load_ (sts, obj, false);
    sts.load_delayed (0);
    l.unlock ();
    callback (db, obj, callback_event::post_load);
    reference_cache_traits::load (pos);
    ig.release ();
    return true;
  }

  bool access::object_traits_impl< ::system_info, id_mysql >::
  reload (database& db, object_type& obj)
  {
    using namespace mysql;

    mysql::connection& conn (
      mysql::transaction::current ().connection ());
    statements_type& sts (
      conn.statement_cache ().find_object<object_type> ());

    statements_type::auto_lock l (sts);

    const id_type& id  (
      obj.conf_key_);

    if (!find_ (sts, &id))
      return false;

    select_statement& st (sts.find_statement ());
    ODB_POTENTIALLY_UNUSED (st);

    callback (db, obj, callback_event::pre_load);
    init (obj, sts.image (), &db);
    load_ (sts, obj, true);
    sts.load_delayed (0);
    l.unlock ();
    callback (db, obj, callback_event::post_load);
    return true;
  }

  bool access::object_traits_impl< ::system_info, id_mysql >::
  find_ (statements_type& sts,
         const id_type* id)
  {
    using namespace mysql;

    id_image_type& i (sts.id_image ());
    init (i, *id);

    binding& idb (sts.id_image_binding ());
    if (i.version != sts.id_image_version () || idb.version == 0)
    {
      bind (idb.bind, i);
      sts.id_image_version (i.version);
      idb.version++;
    }

    image_type& im (sts.image ());
    binding& imb (sts.select_image_binding ());

    if (im.version != sts.select_image_version () ||
        imb.version == 0)
    {
      bind (imb.bind, im, statement_select);
      sts.select_image_version (im.version);
      imb.version++;
    }

    select_statement& st (sts.find_statement ());

    st.execute ();
    auto_result ar (st);
    select_statement::result r (st.fetch ());

    if (r == select_statement::truncated)
    {
      if (grow (im, sts.select_image_truncated ()))
        im.version++;

      if (im.version != sts.select_image_version ())
      {
        bind (imb.bind, im, statement_select);
        sts.select_image_version (im.version);
        imb.version++;
        st.refetch ();
      }
    }

    return r != select_statement::no_data;
  }

  result< access::object_traits_impl< ::system_info, id_mysql >::object_type >
  access::object_traits_impl< ::system_info, id_mysql >::
  query (database&, const query_base_type& q)
  {
    using namespace mysql;
    using odb::details::shared;
    using odb::details::shared_ptr;

    mysql::connection& conn (
      mysql::transaction::current ().connection ());

    statements_type& sts (
      conn.statement_cache ().find_object<object_type> ());

    image_type& im (sts.image ());
    binding& imb (sts.select_image_binding ());

    if (im.version != sts.select_image_version () ||
        imb.version == 0)
    {
      bind (imb.bind, im, statement_select);
      sts.select_image_version (im.version);
      imb.version++;
    }

    std::string text (query_statement);
    if (!q.empty ())
    {
      text += " ";
      text += q.clause ();
    }

    q.init_parameters ();
    shared_ptr<select_statement> st (
      new (shared) select_statement (
        conn,
        text,
        false,
        true,
        q.parameters_binding (),
        imb));

    st->execute ();

    shared_ptr< odb::object_result_impl<object_type> > r (
      new (shared) mysql::object_result_impl<object_type> (
        q, st, sts, 0));

    return result<object_type> (r);
  }

  unsigned long long access::object_traits_impl< ::system_info, id_mysql >::
  erase_query (database&, const query_base_type& q)
  {
    using namespace mysql;

    mysql::connection& conn (
      mysql::transaction::current ().connection ());

    std::string text (erase_query_statement);
    if (!q.empty ())
    {
      text += ' ';
      text += q.clause ();
    }

    q.init_parameters ();
    delete_statement st (
      conn,
      text,
      q.parameters_binding ());

    return st.execute ();
  }
}

#include <odb/post.hxx>
