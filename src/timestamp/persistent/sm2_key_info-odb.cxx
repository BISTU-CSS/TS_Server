// This file was generated by ODB, object-relational mapping (ORM)
// compiler for C++.
//

#include <odb/pre.hxx>

#include "sm2_key_info-odb.hxx"

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
  // sm2_key_info
  //

  struct access::object_traits_impl< ::sm2_key_info, id_mysql >::extra_statement_cache_type
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

  access::object_traits_impl< ::sm2_key_info, id_mysql >::id_type
  access::object_traits_impl< ::sm2_key_info, id_mysql >::
  id (const id_image_type& i)
  {
    mysql::database* db (0);
    ODB_POTENTIALLY_UNUSED (db);

    id_type id;
    {
      mysql::value_traits<
          int,
          mysql::id_long >::set_value (
        id,
        i.id_value,
        i.id_null);
    }

    return id;
  }

  access::object_traits_impl< ::sm2_key_info, id_mysql >::id_type
  access::object_traits_impl< ::sm2_key_info, id_mysql >::
  id (const image_type& i)
  {
    mysql::database* db (0);
    ODB_POTENTIALLY_UNUSED (db);

    id_type id;
    {
      mysql::value_traits<
          int,
          mysql::id_long >::set_value (
        id,
        i.key_id_value,
        i.key_id_null);
    }

    return id;
  }

  bool access::object_traits_impl< ::sm2_key_info, id_mysql >::
  grow (image_type& i,
        my_bool* t)
  {
    ODB_POTENTIALLY_UNUSED (i);
    ODB_POTENTIALLY_UNUSED (t);

    bool grew (false);

    // key_id_
    //
    t[0UL] = 0;

    // key_purpose_
    //
    t[1UL] = 0;

    // key_mod_
    //
    t[2UL] = 0;

    // pri_D_
    //
    if (t[3UL])
    {
      i.pri_D_value.capacity (i.pri_D_size);
      grew = true;
    }

    // pub_X_
    //
    if (t[4UL])
    {
      i.pub_X_value.capacity (i.pub_X_size);
      grew = true;
    }

    // pub_Y_
    //
    if (t[5UL])
    {
      i.pub_Y_value.capacity (i.pub_Y_size);
      grew = true;
    }

    return grew;
  }

  void access::object_traits_impl< ::sm2_key_info, id_mysql >::
  bind (MYSQL_BIND* b,
        image_type& i,
        mysql::statement_kind sk)
  {
    ODB_POTENTIALLY_UNUSED (sk);

    using namespace mysql;

    std::size_t n (0);

    // key_id_
    //
    if (sk != statement_update)
    {
      b[n].buffer_type = MYSQL_TYPE_LONG;
      b[n].is_unsigned = 0;
      b[n].buffer = &i.key_id_value;
      b[n].is_null = &i.key_id_null;
      n++;
    }

    // key_purpose_
    //
    b[n].buffer_type = MYSQL_TYPE_LONG;
    b[n].is_unsigned = 0;
    b[n].buffer = &i.key_purpose_value;
    b[n].is_null = &i.key_purpose_null;
    n++;

    // key_mod_
    //
    b[n].buffer_type = MYSQL_TYPE_LONG;
    b[n].is_unsigned = 0;
    b[n].buffer = &i.key_mod_value;
    b[n].is_null = &i.key_mod_null;
    n++;

    // pri_D_
    //
    b[n].buffer_type = MYSQL_TYPE_STRING;
    b[n].buffer = i.pri_D_value.data ();
    b[n].buffer_length = static_cast<unsigned long> (
      i.pri_D_value.capacity ());
    b[n].length = &i.pri_D_size;
    b[n].is_null = &i.pri_D_null;
    n++;

    // pub_X_
    //
    b[n].buffer_type = MYSQL_TYPE_STRING;
    b[n].buffer = i.pub_X_value.data ();
    b[n].buffer_length = static_cast<unsigned long> (
      i.pub_X_value.capacity ());
    b[n].length = &i.pub_X_size;
    b[n].is_null = &i.pub_X_null;
    n++;

    // pub_Y_
    //
    b[n].buffer_type = MYSQL_TYPE_STRING;
    b[n].buffer = i.pub_Y_value.data ();
    b[n].buffer_length = static_cast<unsigned long> (
      i.pub_Y_value.capacity ());
    b[n].length = &i.pub_Y_size;
    b[n].is_null = &i.pub_Y_null;
    n++;
  }

  void access::object_traits_impl< ::sm2_key_info, id_mysql >::
  bind (MYSQL_BIND* b, id_image_type& i)
  {
    std::size_t n (0);
    b[n].buffer_type = MYSQL_TYPE_LONG;
    b[n].is_unsigned = 0;
    b[n].buffer = &i.id_value;
    b[n].is_null = &i.id_null;
  }

  bool access::object_traits_impl< ::sm2_key_info, id_mysql >::
  init (image_type& i,
        const object_type& o,
        mysql::statement_kind sk)
  {
    ODB_POTENTIALLY_UNUSED (i);
    ODB_POTENTIALLY_UNUSED (o);
    ODB_POTENTIALLY_UNUSED (sk);

    using namespace mysql;

    bool grew (false);

    // key_id_
    //
    if (sk == statement_insert)
    {
      int const& v =
        o.key_id_;

      bool is_null (false);
      mysql::value_traits<
          int,
          mysql::id_long >::set_image (
        i.key_id_value, is_null, v);
      i.key_id_null = is_null;
    }

    // key_purpose_
    //
    {
      int const& v =
        o.key_purpose_;

      bool is_null (false);
      mysql::value_traits<
          int,
          mysql::id_long >::set_image (
        i.key_purpose_value, is_null, v);
      i.key_purpose_null = is_null;
    }

    // key_mod_
    //
    {
      int const& v =
        o.key_mod_;

      bool is_null (false);
      mysql::value_traits<
          int,
          mysql::id_long >::set_image (
        i.key_mod_value, is_null, v);
      i.key_mod_null = is_null;
    }

    // pri_D_
    //
    {
      ::std::string const& v =
        o.pri_D_;

      bool is_null (false);
      std::size_t size (0);
      std::size_t cap (i.pri_D_value.capacity ());
      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_image (
        i.pri_D_value,
        size,
        is_null,
        v);
      i.pri_D_null = is_null;
      i.pri_D_size = static_cast<unsigned long> (size);
      grew = grew || (cap != i.pri_D_value.capacity ());
    }

    // pub_X_
    //
    {
      ::std::string const& v =
        o.pub_X_;

      bool is_null (false);
      std::size_t size (0);
      std::size_t cap (i.pub_X_value.capacity ());
      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_image (
        i.pub_X_value,
        size,
        is_null,
        v);
      i.pub_X_null = is_null;
      i.pub_X_size = static_cast<unsigned long> (size);
      grew = grew || (cap != i.pub_X_value.capacity ());
    }

    // pub_Y_
    //
    {
      ::std::string const& v =
        o.pub_Y_;

      bool is_null (false);
      std::size_t size (0);
      std::size_t cap (i.pub_Y_value.capacity ());
      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_image (
        i.pub_Y_value,
        size,
        is_null,
        v);
      i.pub_Y_null = is_null;
      i.pub_Y_size = static_cast<unsigned long> (size);
      grew = grew || (cap != i.pub_Y_value.capacity ());
    }

    return grew;
  }

  void access::object_traits_impl< ::sm2_key_info, id_mysql >::
  init (object_type& o,
        const image_type& i,
        database* db)
  {
    ODB_POTENTIALLY_UNUSED (o);
    ODB_POTENTIALLY_UNUSED (i);
    ODB_POTENTIALLY_UNUSED (db);

    // key_id_
    //
    {
      int& v =
        o.key_id_;

      mysql::value_traits<
          int,
          mysql::id_long >::set_value (
        v,
        i.key_id_value,
        i.key_id_null);
    }

    // key_purpose_
    //
    {
      int& v =
        o.key_purpose_;

      mysql::value_traits<
          int,
          mysql::id_long >::set_value (
        v,
        i.key_purpose_value,
        i.key_purpose_null);
    }

    // key_mod_
    //
    {
      int& v =
        o.key_mod_;

      mysql::value_traits<
          int,
          mysql::id_long >::set_value (
        v,
        i.key_mod_value,
        i.key_mod_null);
    }

    // pri_D_
    //
    {
      ::std::string& v =
        o.pri_D_;

      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_value (
        v,
        i.pri_D_value,
        i.pri_D_size,
        i.pri_D_null);
    }

    // pub_X_
    //
    {
      ::std::string& v =
        o.pub_X_;

      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_value (
        v,
        i.pub_X_value,
        i.pub_X_size,
        i.pub_X_null);
    }

    // pub_Y_
    //
    {
      ::std::string& v =
        o.pub_Y_;

      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_value (
        v,
        i.pub_Y_value,
        i.pub_Y_size,
        i.pub_Y_null);
    }
  }

  void access::object_traits_impl< ::sm2_key_info, id_mysql >::
  init (id_image_type& i, const id_type& id)
  {
    {
      bool is_null (false);
      mysql::value_traits<
          int,
          mysql::id_long >::set_image (
        i.id_value, is_null, id);
      i.id_null = is_null;
    }
  }

  const char access::object_traits_impl< ::sm2_key_info, id_mysql >::persist_statement[] =
  "INSERT INTO `sm2_key_info` "
  "(`key_id`, "
  "`key_purpose`, "
  "`key_mod`, "
  "`pri_D`, "
  "`pub_X`, "
  "`pub_Y`) "
  "VALUES "
  "(?, ?, ?, ?, ?, ?)";

  const char access::object_traits_impl< ::sm2_key_info, id_mysql >::find_statement[] =
  "SELECT "
  "`sm2_key_info`.`key_id`, "
  "`sm2_key_info`.`key_purpose`, "
  "`sm2_key_info`.`key_mod`, "
  "`sm2_key_info`.`pri_D`, "
  "`sm2_key_info`.`pub_X`, "
  "`sm2_key_info`.`pub_Y` "
  "FROM `sm2_key_info` "
  "WHERE `sm2_key_info`.`key_id`=?";

  const char access::object_traits_impl< ::sm2_key_info, id_mysql >::update_statement[] =
  "UPDATE `sm2_key_info` "
  "SET "
  "`key_purpose`=?, "
  "`key_mod`=?, "
  "`pri_D`=?, "
  "`pub_X`=?, "
  "`pub_Y`=? "
  "WHERE `key_id`=?";

  const char access::object_traits_impl< ::sm2_key_info, id_mysql >::erase_statement[] =
  "DELETE FROM `sm2_key_info` "
  "WHERE `key_id`=?";

  const char access::object_traits_impl< ::sm2_key_info, id_mysql >::query_statement[] =
  "SELECT "
  "`sm2_key_info`.`key_id`, "
  "`sm2_key_info`.`key_purpose`, "
  "`sm2_key_info`.`key_mod`, "
  "`sm2_key_info`.`pri_D`, "
  "`sm2_key_info`.`pub_X`, "
  "`sm2_key_info`.`pub_Y` "
  "FROM `sm2_key_info`";

  const char access::object_traits_impl< ::sm2_key_info, id_mysql >::erase_query_statement[] =
  "DELETE FROM `sm2_key_info`";

  const char access::object_traits_impl< ::sm2_key_info, id_mysql >::table_name[] =
  "`sm2_key_info`";

  void access::object_traits_impl< ::sm2_key_info, id_mysql >::
  persist (database& db, object_type& obj)
  {
    ODB_POTENTIALLY_UNUSED (db);

    using namespace mysql;

    mysql::connection& conn (
      mysql::transaction::current ().connection ());
    statements_type& sts (
      conn.statement_cache ().find_object<object_type> ());

    callback (db,
              static_cast<const object_type&> (obj),
              callback_event::pre_persist);

    image_type& im (sts.image ());
    binding& imb (sts.insert_image_binding ());

    if (init (im, obj, statement_insert))
      im.version++;

    im.key_id_value = 0;

    if (im.version != sts.insert_image_version () ||
        imb.version == 0)
    {
      bind (imb.bind, im, statement_insert);
      sts.insert_image_version (im.version);
      imb.version++;
    }

    {
      id_image_type& i (sts.id_image ());
      binding& b (sts.id_image_binding ());
      if (i.version != sts.id_image_version () || b.version == 0)
      {
        bind (b.bind, i);
        sts.id_image_version (i.version);
        b.version++;
      }
    }

    insert_statement& st (sts.persist_statement ());
    if (!st.execute ())
      throw object_already_persistent ();

    obj.key_id_ = id (sts.id_image ());

    callback (db,
              static_cast<const object_type&> (obj),
              callback_event::post_persist);
  }

  void access::object_traits_impl< ::sm2_key_info, id_mysql >::
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
      obj.key_id_);
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

  void access::object_traits_impl< ::sm2_key_info, id_mysql >::
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

  access::object_traits_impl< ::sm2_key_info, id_mysql >::pointer_type
  access::object_traits_impl< ::sm2_key_info, id_mysql >::
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

  bool access::object_traits_impl< ::sm2_key_info, id_mysql >::
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

  bool access::object_traits_impl< ::sm2_key_info, id_mysql >::
  reload (database& db, object_type& obj)
  {
    using namespace mysql;

    mysql::connection& conn (
      mysql::transaction::current ().connection ());
    statements_type& sts (
      conn.statement_cache ().find_object<object_type> ());

    statements_type::auto_lock l (sts);

    const id_type& id  (
      obj.key_id_);

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

  bool access::object_traits_impl< ::sm2_key_info, id_mysql >::
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

  result< access::object_traits_impl< ::sm2_key_info, id_mysql >::object_type >
  access::object_traits_impl< ::sm2_key_info, id_mysql >::
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

  unsigned long long access::object_traits_impl< ::sm2_key_info, id_mysql >::
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