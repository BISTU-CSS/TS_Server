// This file was generated by ODB, object-relational mapping (ORM)
// compiler for C++.
//

#include <odb/pre.hxx>

#include "timestamp_log-odb.hxx"

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
  // timestamp_log
  //

  struct access::object_traits_impl< ::timestamp_log, id_mysql >::extra_statement_cache_type
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

  access::object_traits_impl< ::timestamp_log, id_mysql >::id_type
  access::object_traits_impl< ::timestamp_log, id_mysql >::
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

  access::object_traits_impl< ::timestamp_log, id_mysql >::id_type
  access::object_traits_impl< ::timestamp_log, id_mysql >::
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
        i.id_value,
        i.id_null);
    }

    return id;
  }

  bool access::object_traits_impl< ::timestamp_log, id_mysql >::
  grow (image_type& i,
        my_bool* t)
  {
    ODB_POTENTIALLY_UNUSED (i);
    ODB_POTENTIALLY_UNUSED (t);

    bool grew (false);

    // id_
    //
    t[0UL] = 0;

    // ts_issue_
    //
    if (t[1UL])
    {
      i.ts_issue_value.capacity (i.ts_issue_size);
      grew = true;
    }

    // ts_certificate_
    //
    if (t[2UL])
    {
      i.ts_certificate_value.capacity (i.ts_certificate_size);
      grew = true;
    }

    // ts_time_
    //
    if (t[3UL])
    {
      i.ts_time_value.capacity (i.ts_time_size);
      grew = true;
    }

    // user_ip_
    //
    if (t[4UL])
    {
      i.user_ip_value.capacity (i.user_ip_size);
      grew = true;
    }

    // ts_status_
    //
    if (t[5UL])
    {
      i.ts_status_value.capacity (i.ts_status_size);
      grew = true;
    }

    // ts_info_
    //
    if (t[6UL])
    {
      i.ts_info_value.capacity (i.ts_info_size);
      grew = true;
    }

    return grew;
  }

  void access::object_traits_impl< ::timestamp_log, id_mysql >::
  bind (MYSQL_BIND* b,
        image_type& i,
        mysql::statement_kind sk)
  {
    ODB_POTENTIALLY_UNUSED (sk);

    using namespace mysql;

    std::size_t n (0);

    // id_
    //
    if (sk != statement_update)
    {
      b[n].buffer_type = MYSQL_TYPE_LONG;
      b[n].is_unsigned = 0;
      b[n].buffer = &i.id_value;
      b[n].is_null = &i.id_null;
      n++;
    }

    // ts_issue_
    //
    b[n].buffer_type = MYSQL_TYPE_STRING;
    b[n].buffer = i.ts_issue_value.data ();
    b[n].buffer_length = static_cast<unsigned long> (
      i.ts_issue_value.capacity ());
    b[n].length = &i.ts_issue_size;
    b[n].is_null = &i.ts_issue_null;
    n++;

    // ts_certificate_
    //
    b[n].buffer_type = MYSQL_TYPE_STRING;
    b[n].buffer = i.ts_certificate_value.data ();
    b[n].buffer_length = static_cast<unsigned long> (
      i.ts_certificate_value.capacity ());
    b[n].length = &i.ts_certificate_size;
    b[n].is_null = &i.ts_certificate_null;
    n++;

    // ts_time_
    //
    b[n].buffer_type = MYSQL_TYPE_STRING;
    b[n].buffer = i.ts_time_value.data ();
    b[n].buffer_length = static_cast<unsigned long> (
      i.ts_time_value.capacity ());
    b[n].length = &i.ts_time_size;
    b[n].is_null = &i.ts_time_null;
    n++;

    // user_ip_
    //
    b[n].buffer_type = MYSQL_TYPE_STRING;
    b[n].buffer = i.user_ip_value.data ();
    b[n].buffer_length = static_cast<unsigned long> (
      i.user_ip_value.capacity ());
    b[n].length = &i.user_ip_size;
    b[n].is_null = &i.user_ip_null;
    n++;

    // ts_status_
    //
    b[n].buffer_type = MYSQL_TYPE_STRING;
    b[n].buffer = i.ts_status_value.data ();
    b[n].buffer_length = static_cast<unsigned long> (
      i.ts_status_value.capacity ());
    b[n].length = &i.ts_status_size;
    b[n].is_null = &i.ts_status_null;
    n++;

    // ts_info_
    //
    b[n].buffer_type = MYSQL_TYPE_STRING;
    b[n].buffer = i.ts_info_value.data ();
    b[n].buffer_length = static_cast<unsigned long> (
      i.ts_info_value.capacity ());
    b[n].length = &i.ts_info_size;
    b[n].is_null = &i.ts_info_null;
    n++;
  }

  void access::object_traits_impl< ::timestamp_log, id_mysql >::
  bind (MYSQL_BIND* b, id_image_type& i)
  {
    std::size_t n (0);
    b[n].buffer_type = MYSQL_TYPE_LONG;
    b[n].is_unsigned = 0;
    b[n].buffer = &i.id_value;
    b[n].is_null = &i.id_null;
  }

  bool access::object_traits_impl< ::timestamp_log, id_mysql >::
  init (image_type& i,
        const object_type& o,
        mysql::statement_kind sk)
  {
    ODB_POTENTIALLY_UNUSED (i);
    ODB_POTENTIALLY_UNUSED (o);
    ODB_POTENTIALLY_UNUSED (sk);

    using namespace mysql;

    bool grew (false);

    // id_
    //
    if (sk == statement_insert)
    {
      int const& v =
        o.id_;

      bool is_null (false);
      mysql::value_traits<
          int,
          mysql::id_long >::set_image (
        i.id_value, is_null, v);
      i.id_null = is_null;
    }

    // ts_issue_
    //
    {
      ::std::string const& v =
        o.ts_issue_;

      bool is_null (false);
      std::size_t size (0);
      std::size_t cap (i.ts_issue_value.capacity ());
      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_image (
        i.ts_issue_value,
        size,
        is_null,
        v);
      i.ts_issue_null = is_null;
      i.ts_issue_size = static_cast<unsigned long> (size);
      grew = grew || (cap != i.ts_issue_value.capacity ());
    }

    // ts_certificate_
    //
    {
      ::std::string const& v =
        o.ts_certificate_;

      bool is_null (false);
      std::size_t size (0);
      std::size_t cap (i.ts_certificate_value.capacity ());
      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_image (
        i.ts_certificate_value,
        size,
        is_null,
        v);
      i.ts_certificate_null = is_null;
      i.ts_certificate_size = static_cast<unsigned long> (size);
      grew = grew || (cap != i.ts_certificate_value.capacity ());
    }

    // ts_time_
    //
    {
      ::std::string const& v =
        o.ts_time_;

      bool is_null (false);
      std::size_t size (0);
      std::size_t cap (i.ts_time_value.capacity ());
      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_image (
        i.ts_time_value,
        size,
        is_null,
        v);
      i.ts_time_null = is_null;
      i.ts_time_size = static_cast<unsigned long> (size);
      grew = grew || (cap != i.ts_time_value.capacity ());
    }

    // user_ip_
    //
    {
      ::std::string const& v =
        o.user_ip_;

      bool is_null (false);
      std::size_t size (0);
      std::size_t cap (i.user_ip_value.capacity ());
      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_image (
        i.user_ip_value,
        size,
        is_null,
        v);
      i.user_ip_null = is_null;
      i.user_ip_size = static_cast<unsigned long> (size);
      grew = grew || (cap != i.user_ip_value.capacity ());
    }

    // ts_status_
    //
    {
      ::std::string const& v =
        o.ts_status_;

      bool is_null (false);
      std::size_t size (0);
      std::size_t cap (i.ts_status_value.capacity ());
      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_image (
        i.ts_status_value,
        size,
        is_null,
        v);
      i.ts_status_null = is_null;
      i.ts_status_size = static_cast<unsigned long> (size);
      grew = grew || (cap != i.ts_status_value.capacity ());
    }

    // ts_info_
    //
    {
      ::std::string const& v =
        o.ts_info_;

      bool is_null (false);
      std::size_t size (0);
      std::size_t cap (i.ts_info_value.capacity ());
      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_image (
        i.ts_info_value,
        size,
        is_null,
        v);
      i.ts_info_null = is_null;
      i.ts_info_size = static_cast<unsigned long> (size);
      grew = grew || (cap != i.ts_info_value.capacity ());
    }

    return grew;
  }

  void access::object_traits_impl< ::timestamp_log, id_mysql >::
  init (object_type& o,
        const image_type& i,
        database* db)
  {
    ODB_POTENTIALLY_UNUSED (o);
    ODB_POTENTIALLY_UNUSED (i);
    ODB_POTENTIALLY_UNUSED (db);

    // id_
    //
    {
      int& v =
        o.id_;

      mysql::value_traits<
          int,
          mysql::id_long >::set_value (
        v,
        i.id_value,
        i.id_null);
    }

    // ts_issue_
    //
    {
      ::std::string& v =
        o.ts_issue_;

      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_value (
        v,
        i.ts_issue_value,
        i.ts_issue_size,
        i.ts_issue_null);
    }

    // ts_certificate_
    //
    {
      ::std::string& v =
        o.ts_certificate_;

      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_value (
        v,
        i.ts_certificate_value,
        i.ts_certificate_size,
        i.ts_certificate_null);
    }

    // ts_time_
    //
    {
      ::std::string& v =
        o.ts_time_;

      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_value (
        v,
        i.ts_time_value,
        i.ts_time_size,
        i.ts_time_null);
    }

    // user_ip_
    //
    {
      ::std::string& v =
        o.user_ip_;

      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_value (
        v,
        i.user_ip_value,
        i.user_ip_size,
        i.user_ip_null);
    }

    // ts_status_
    //
    {
      ::std::string& v =
        o.ts_status_;

      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_value (
        v,
        i.ts_status_value,
        i.ts_status_size,
        i.ts_status_null);
    }

    // ts_info_
    //
    {
      ::std::string& v =
        o.ts_info_;

      mysql::value_traits<
          ::std::string,
          mysql::id_string >::set_value (
        v,
        i.ts_info_value,
        i.ts_info_size,
        i.ts_info_null);
    }
  }

  void access::object_traits_impl< ::timestamp_log, id_mysql >::
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

  const char access::object_traits_impl< ::timestamp_log, id_mysql >::persist_statement[] =
  "INSERT INTO `timestamp_log` "
  "(`id`, "
  "`ts_issue`, "
  "`ts_certificate`, "
  "`ts_time`, "
  "`user_ip`, "
  "`ts_status`, "
  "`ts_info`) "
  "VALUES "
  "(?, ?, ?, ?, ?, ?, ?)";

  const char access::object_traits_impl< ::timestamp_log, id_mysql >::find_statement[] =
  "SELECT "
  "`timestamp_log`.`id`, "
  "`timestamp_log`.`ts_issue`, "
  "`timestamp_log`.`ts_certificate`, "
  "`timestamp_log`.`ts_time`, "
  "`timestamp_log`.`user_ip`, "
  "`timestamp_log`.`ts_status`, "
  "`timestamp_log`.`ts_info` "
  "FROM `timestamp_log` "
  "WHERE `timestamp_log`.`id`=?";

  const char access::object_traits_impl< ::timestamp_log, id_mysql >::update_statement[] =
  "UPDATE `timestamp_log` "
  "SET "
  "`ts_issue`=?, "
  "`ts_certificate`=?, "
  "`ts_time`=?, "
  "`user_ip`=?, "
  "`ts_status`=?, "
  "`ts_info`=? "
  "WHERE `id`=?";

  const char access::object_traits_impl< ::timestamp_log, id_mysql >::erase_statement[] =
  "DELETE FROM `timestamp_log` "
  "WHERE `id`=?";

  const char access::object_traits_impl< ::timestamp_log, id_mysql >::query_statement[] =
  "SELECT "
  "`timestamp_log`.`id`, "
  "`timestamp_log`.`ts_issue`, "
  "`timestamp_log`.`ts_certificate`, "
  "`timestamp_log`.`ts_time`, "
  "`timestamp_log`.`user_ip`, "
  "`timestamp_log`.`ts_status`, "
  "`timestamp_log`.`ts_info` "
  "FROM `timestamp_log`";

  const char access::object_traits_impl< ::timestamp_log, id_mysql >::erase_query_statement[] =
  "DELETE FROM `timestamp_log`";

  const char access::object_traits_impl< ::timestamp_log, id_mysql >::table_name[] =
  "`timestamp_log`";

  void access::object_traits_impl< ::timestamp_log, id_mysql >::
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

    im.id_value = 0;

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

    obj.id_ = id (sts.id_image ());

    callback (db,
              static_cast<const object_type&> (obj),
              callback_event::post_persist);
  }

  void access::object_traits_impl< ::timestamp_log, id_mysql >::
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
      obj.id_);
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

  void access::object_traits_impl< ::timestamp_log, id_mysql >::
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

  access::object_traits_impl< ::timestamp_log, id_mysql >::pointer_type
  access::object_traits_impl< ::timestamp_log, id_mysql >::
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

  bool access::object_traits_impl< ::timestamp_log, id_mysql >::
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

  bool access::object_traits_impl< ::timestamp_log, id_mysql >::
  reload (database& db, object_type& obj)
  {
    using namespace mysql;

    mysql::connection& conn (
      mysql::transaction::current ().connection ());
    statements_type& sts (
      conn.statement_cache ().find_object<object_type> ());

    statements_type::auto_lock l (sts);

    const id_type& id  (
      obj.id_);

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

  bool access::object_traits_impl< ::timestamp_log, id_mysql >::
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

  result< access::object_traits_impl< ::timestamp_log, id_mysql >::object_type >
  access::object_traits_impl< ::timestamp_log, id_mysql >::
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

  unsigned long long access::object_traits_impl< ::timestamp_log, id_mysql >::
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