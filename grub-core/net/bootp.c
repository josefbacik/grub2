/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010,2011  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/net.h>
#include <grub/env.h>
#include <grub/i18n.h>
#include <grub/command.h>
#include <grub/net/ip.h>
#include <grub/net/netbuff.h>
#include <grub/net/udp.h>
#include <grub/datetime.h>
#include <grub/time.h>

static void
parse_dhcp_vendor (const char *name, const void *vend, int limit, int *mask)
{
  const grub_uint8_t *ptr, *ptr0;

  ptr = ptr0 = vend;

  if (ptr[0] != GRUB_NET_BOOTP_RFC1048_MAGIC_0
      || ptr[1] != GRUB_NET_BOOTP_RFC1048_MAGIC_1
      || ptr[2] != GRUB_NET_BOOTP_RFC1048_MAGIC_2
      || ptr[3] != GRUB_NET_BOOTP_RFC1048_MAGIC_3)
    return;
  ptr = ptr + sizeof (grub_uint32_t);
  while (ptr - ptr0 < limit)
    {
      grub_uint8_t tagtype;
      grub_uint8_t taglength;

      tagtype = *ptr++;

      /* Pad tag.  */
      if (tagtype == GRUB_NET_BOOTP_PAD)
	continue;

      /* End tag.  */
      if (tagtype == GRUB_NET_BOOTP_END)
	return;

      taglength = *ptr++;

      switch (tagtype)
	{
	case GRUB_NET_BOOTP_NETMASK:
	  if (taglength == 4)
	    {
	      int i;
	      for (i = 0; i < 32; i++)
		if (!(ptr[i / 8] & (1 << (7 - (i % 8)))))
		  break;
	      *mask = i;
	    }
	  break;

	case GRUB_NET_BOOTP_ROUTER:
	  if (taglength == 4)
	    {
	      grub_net_network_level_netaddress_t target;
	      grub_net_network_level_address_t gw;
	      char *rname;
	      
	      target.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
	      target.ipv4.base = 0;
	      target.ipv4.masksize = 0;
	      gw.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
	      grub_memcpy (&gw.ipv4, ptr, sizeof (gw.ipv4));
	      rname = grub_xasprintf ("%s:default", name);
	      if (rname)
		grub_net_add_route_gw (rname, target, gw, NULL);
	      grub_free (rname);
	    }
	  break;
	case GRUB_NET_BOOTP_DNS:
	  {
	    int i;
	    for (i = 0; i < taglength / 4; i++)
	      {
		struct grub_net_network_level_address s;
		s.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
		s.ipv4 = grub_get_unaligned32 (ptr);
		s.option = DNS_OPTION_PREFER_IPV4;
		grub_net_add_dns_server (&s);
		ptr += 4;
	      }
	  }
	  continue;
	case GRUB_NET_BOOTP_HOSTNAME:
          grub_env_set_net_property (name, "hostname", (const char *) ptr,
                                     taglength);
          break;

	case GRUB_NET_BOOTP_DOMAIN:
          grub_env_set_net_property (name, "domain", (const char *) ptr,
                                     taglength);
          break;

	case GRUB_NET_BOOTP_ROOT_PATH:
          grub_env_set_net_property (name, "rootpath", (const char *) ptr,
                                     taglength);
          break;

	case GRUB_NET_BOOTP_EXTENSIONS_PATH:
          grub_env_set_net_property (name, "extensionspath", (const char *) ptr,
                                     taglength);
          break;

	  /* If you need any other options please contact GRUB
	     development team.  */
	}

      ptr += taglength;
    }
}

#define OFFSET_OF(x, y) ((grub_size_t)((grub_uint8_t *)((y)->x) - (grub_uint8_t *)(y)))

struct grub_net_network_level_interface *
grub_net_configure_by_dhcp_ack (const char *name,
				struct grub_net_card *card,
				grub_net_interface_flags_t flags,
				const struct grub_net_bootp_packet *bp,
				grub_size_t size,
				int is_def, char **device, char **path)
{
  grub_net_network_level_address_t addr;
  grub_net_link_level_address_t hwaddr;
  struct grub_net_network_level_interface *inter;
  int mask = -1;

  addr.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
  addr.ipv4 = bp->your_ip;

  if (device)
    *device = 0;
  if (path)
    *path = 0;

  grub_memcpy (hwaddr.mac, bp->mac_addr,
	       bp->hw_len < sizeof (hwaddr.mac) ? bp->hw_len
	       : sizeof (hwaddr.mac));
  hwaddr.type = GRUB_NET_LINK_LEVEL_PROTOCOL_ETHERNET;

  inter = grub_net_add_addr (name, card, &addr, &hwaddr, flags);
#if 0
  /* This is likely based on misunderstanding. gateway_ip refers to
     address of BOOTP relay and should not be used after BOOTP transaction
     is complete.
     See RFC1542, 3.4 Interpretation of the 'giaddr' field
   */
  if (bp->gateway_ip)
    {
      grub_net_network_level_netaddress_t target;
      grub_net_network_level_address_t gw;
      char *rname;
	  
      target.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
      target.ipv4.base = bp->server_ip;
      target.ipv4.masksize = 32;
      gw.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
      gw.ipv4 = bp->gateway_ip;
      rname = grub_xasprintf ("%s:gw", name);
      if (rname)
	grub_net_add_route_gw (rname, target, gw);
      grub_free (rname);

      target.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
      target.ipv4.base = bp->gateway_ip;
      target.ipv4.masksize = 32;
      grub_net_add_route (name, target, inter);
    }
#endif

  if (size > OFFSET_OF (boot_file, bp))
    grub_env_set_net_property (name, "boot_file", bp->boot_file,
                               sizeof (bp->boot_file));
  if (is_def)
    grub_net_default_server = 0;
  if (is_def && !grub_net_default_server && bp->server_ip)
    {
      grub_net_default_server = grub_xasprintf ("%d.%d.%d.%d",
						((grub_uint8_t *) &bp->server_ip)[0],
						((grub_uint8_t *) &bp->server_ip)[1],
						((grub_uint8_t *) &bp->server_ip)[2],
						((grub_uint8_t *) &bp->server_ip)[3]);
      grub_print_error ();
    }

  if (is_def)
    {
      grub_env_set ("net_default_interface", name);
      grub_env_export ("net_default_interface");
    }

  if (device && !*device && bp->server_ip)
    {
      *device = grub_xasprintf ("tftp,%d.%d.%d.%d",
				((grub_uint8_t *) &bp->server_ip)[0],
				((grub_uint8_t *) &bp->server_ip)[1],
				((grub_uint8_t *) &bp->server_ip)[2],
				((grub_uint8_t *) &bp->server_ip)[3]);
      grub_print_error ();
    }
  if (size > OFFSET_OF (server_name, bp)
      && bp->server_name[0])
    {
      grub_env_set_net_property (name, "dhcp_server_name", bp->server_name,
                                 sizeof (bp->server_name));
      if (is_def && !grub_net_default_server)
	{
	  grub_net_default_server = grub_strdup (bp->server_name);
	  grub_print_error ();
	}
      if (device && !*device)
	{
	  *device = grub_xasprintf ("tftp,%s", bp->server_name);
	  grub_print_error ();
	}
    }

  if (size > OFFSET_OF (boot_file, bp) && path)
    {
      *path = grub_strndup (bp->boot_file, sizeof (bp->boot_file));
      grub_print_error ();
      if (*path)
	{
	  char *slash;
	  slash = grub_strrchr (*path, '/');
	  if (slash)
	    *slash = 0;
	  else
	    **path = 0;
	}
    }
  if (size > OFFSET_OF (vendor, bp))
    parse_dhcp_vendor (name, &bp->vendor, size - OFFSET_OF (vendor, bp), &mask);
  grub_net_add_ipv4_local (inter, mask);
  
  inter->dhcp_ack = grub_malloc (size);
  if (inter->dhcp_ack)
    {
      grub_memcpy (inter->dhcp_ack, bp, size);
      inter->dhcp_acklen = size;
    }
  else
    grub_errno = GRUB_ERR_NONE;

  return inter;
}

struct grub_dhcpv6_option {
  grub_uint16_t code;
  grub_uint16_t len;
  grub_uint8_t data[0];
} GRUB_PACKED;


struct grub_dhcpv6_iana_option {
  grub_uint32_t iaid;
  grub_uint32_t t1;
  grub_uint32_t t2;
  grub_uint8_t data[0];
} GRUB_PACKED;

struct grub_dhcpv6_iaaddr_option {
  grub_uint8_t addr[16];
  grub_uint32_t preferred_lifetime;
  grub_uint32_t valid_lifetime;
  grub_uint8_t data[0];
} GRUB_PACKED;

struct grub_DUID_LL
{
  grub_uint16_t type;
  grub_uint16_t hw_type;
  grub_uint8_t hwaddr[6];
} GRUB_PACKED;

struct grub_dhcpv6_dns_servers {
  grub_uint8_t addr[16];
  grub_uint8_t next_addr[0];
} GRUB_PACKED;

#define DHCPv6_REPLY 7
#define DHCPv6_ADVERTISE 2
#define DHCPv6_REQUEST 3
#define OPTION_BOOTFILE_URL 59
#define OPTION_DNS_SERVERS 23
#define OPTION_IA_NA 3
#define OPTION_IAADDR 5
#define OPTION_CLIENTID 1
#define OPTION_SERVERID 2
#define OPTION_ORO 6
#define OPTION_ELAPSED_TIME 8

struct grub_dhcpv6_session
{
  struct grub_dhcpv6_session *next;
  struct grub_dhcpv6_session **prev;
  grub_uint32_t iaid;
  grub_uint32_t transaction_id:24;
  grub_uint64_t start_time;
  struct grub_net_network_level_interface *ifaces;
};

static struct grub_dhcpv6_session *grub_dhcpv6_sessions = NULL;
#define FOR_DHCPV6_SESSIONS(var) \
    for (var = grub_dhcpv6_sessions ; var; var = var->next)

static void
grub_dhcpv6_session_add (struct grub_dhcpv6_session *session)
{
  struct grub_datetime date;
  grub_err_t err;
  grub_int32_t t = 0;

  err = grub_get_datetime (&date);
  if (err || !grub_datetime2unixtime (&date, &t))
    {
      grub_errno = GRUB_ERR_NONE;
      t = 0;
    }

  session->transaction_id = t;
  session->start_time = grub_get_time_ms ();

  session->prev = &grub_dhcpv6_sessions;
  session->next = grub_dhcpv6_sessions;

  if (session->next)
    session->next->prev = &session->next;

  grub_dhcpv6_sessions = session;
  return;
}

static void
grub_dhcpv6_session_remove (struct grub_dhcpv6_session *session)
{
  *session->prev = session->next;
  if (session->next)
    session->next->prev = session->prev;
  session->next = NULL;
  session->prev = NULL;
  return;
}

static const struct grub_dhcpv6_option*
find_dhcpv6_option (const struct grub_net_dhcpv6_packet *packet,
		    grub_uint16_t option)
{
  grub_uint16_t code, len;
  const struct grub_dhcpv6_option *popt;

  popt = (const struct grub_dhcpv6_option *)packet->dhcp_options;
  code = grub_be_to_cpu16 (popt->code);
  len = grub_be_to_cpu16 (popt->len);

  while (0 != code && option != code)
    {
      popt = (const struct grub_dhcpv6_option *)((grub_uint8_t *)popt +
		len + sizeof(*popt));
      code = grub_be_to_cpu16 (popt->code);
      len = grub_be_to_cpu16 (popt->len);
    }

  if (option == code)
      return popt;

  return NULL;
}

static const grub_uint8_t*
find_dhcpv6_address (const struct grub_net_dhcpv6_packet *packet)
{
  const struct grub_dhcpv6_option* popt = find_dhcpv6_option (packet, OPTION_IA_NA);
  const struct grub_dhcpv6_iana_option *ia_na;
  const struct grub_dhcpv6_option *iaaddr_hdr;
  const struct grub_dhcpv6_iaaddr_option *iaaddr;
  grub_uint16_t ia_na_data_offset, ia_na_data_len, len;

  if (grub_be_to_cpu16 (popt->code) != OPTION_IA_NA)
    {
      grub_error (GRUB_ERR_IO, N_("not an IA_NA DHCPv6 option"));
      return NULL;
    }

  ia_na = (const struct grub_dhcpv6_iana_option *)popt->data;

  if (grub_be_to_cpu16(popt->len) <= sizeof (*ia_na))
    {
      grub_error (GRUB_ERR_IO, N_("invalid size for IAADDR"));
      return NULL;
    }

  ia_na_data_len = grub_be_to_cpu16(popt->len) - sizeof (*ia_na);
  ia_na_data_offset = 0;

  iaaddr_hdr = (const struct grub_dhcpv6_option *) ia_na->data;
  len = grub_be_to_cpu16 (iaaddr_hdr->len);

  while (grub_be_to_cpu16(iaaddr_hdr->code) != OPTION_IAADDR)
    {
      ia_na_data_offset += (len + sizeof (*iaaddr_hdr));

      if (ia_na_data_offset < ia_na_data_len)
	{
	  iaaddr_hdr =(const struct grub_dhcpv6_option *)(ia_na->data +
	    ia_na_data_offset);
	  len = grub_be_to_cpu16 (iaaddr_hdr->len);
	}
      else
	{
	  iaaddr_hdr = NULL;
	  break;
	}
    }

  if (!iaaddr_hdr)
    {
      grub_error (GRUB_ERR_IO, N_("IAADDR not found"));
      return NULL;
    }

  if ((ia_na_data_offset + sizeof (*iaaddr_hdr) + len) > ia_na_data_len)
    {
      grub_error (GRUB_ERR_IO, N_("IAADDR size check failed"));
      return NULL;
    }

  iaaddr = (const struct grub_dhcpv6_iaaddr_option *) iaaddr_hdr->data;

  return iaaddr->addr;
}

static void
get_dhcpv6_dns_address (const struct grub_net_dhcpv6_packet *packet,
	grub_net_network_level_address_t **addr, grub_uint16_t *naddr)
{
  const struct grub_dhcpv6_option* popt;
  const struct grub_dhcpv6_dns_servers *dns;
  grub_uint16_t len;
  const grub_uint8_t *pa;
  int i, ln;
  grub_net_network_level_address_t *la;

  if (addr)
    *addr = NULL;

  if (naddr)
    *naddr = 0;

  popt = find_dhcpv6_option (packet, OPTION_DNS_SERVERS);
  if (!popt)
    return;

  len = grub_be_to_cpu16 (popt->len);
  if ((len % 16) != 0)
    {
      grub_error (GRUB_ERR_IO, N_("invalid dns address length"));
      return;
    }

  dns = (const struct grub_dhcpv6_dns_servers *)popt->data;

  ln = len / 16;
  la = grub_zalloc (sizeof (grub_net_network_level_address_t) * ln);

  for (i = 0, pa = dns->addr; i < ln; i++, pa = dns->next_addr)
    {
      (la + i)->type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV6;
      (la + i)->ipv6[0] = grub_get_unaligned64 (pa);
      (la + i)->ipv6[1] = grub_get_unaligned64 (pa + 8);
      (la + i)->option = DNS_OPTION_PREFER_IPV6;
    }

  *addr = la;
  *naddr = ln;

  return;
}

static void
find_dhcpv6_bootfile_url (const struct grub_net_dhcpv6_packet *packet,
	char **proto, char **server_ip, char **boot_file)
{
  char *bootfile_url;
  const struct grub_dhcpv6_option* opt_url;
  char *ip_start, *ip_end;
  char *path;
  grub_size_t ip_len;
  grub_uint16_t len;
  const char *protos[] = {"tftp://", "http://", NULL};
  const char *pr;
  int i;

  if (proto)
    *proto = NULL;

  if (server_ip)
    *server_ip = NULL;

  if (boot_file)
    *boot_file = NULL;

  opt_url = find_dhcpv6_option (packet, OPTION_BOOTFILE_URL);

  if (!opt_url)
    {
      grub_error (GRUB_ERR_IO, N_("no bootfile-url in DHCPv6 option"));
      return;
    }

  len = grub_be_to_cpu16 (opt_url->len);

  bootfile_url = grub_malloc (len + 1);

  if (!bootfile_url)
    return;

  grub_memcpy (bootfile_url, opt_url->data, len);
  bootfile_url[len]   = '\0';

  for (i = 0; (pr = *(protos + i)); ++i)
      if (grub_strncmp (bootfile_url, pr, grub_strlen(pr)) == 0)
	break;

  if (!pr)
    {
      grub_error (GRUB_ERR_IO,
	N_("unsupported protocol, only tftp and http are supported"));
      goto cleanup;
    }

  ip_start = ip_end = NULL;
  ip_start = bootfile_url + grub_strlen(pr);

  if (*ip_start != '[')
    ip_start = NULL;
  else
    ip_end = grub_strchr (++ip_start, ']');

  if (!ip_start || !ip_end)
    {
      grub_error (GRUB_ERR_IO, N_("IPv6-address not in square brackets"));
      goto cleanup;
    }

  ip_len = ip_end - ip_start;

  if (proto)
    {
      grub_size_t proto_len  = grub_strlen (pr) - 3;

      *proto = grub_malloc (proto_len + 1);
      if (!*proto)
	goto cleanup;

      grub_memcpy (*proto, pr, proto_len);
      *(*proto + proto_len)  = '\0';
    }

  if (server_ip)
    {
      *server_ip = grub_malloc (ip_len + 1);

      if (!*server_ip)
	goto cleanup;

      grub_memcpy (*server_ip, ip_start, ip_len);
      *(*server_ip + ip_len) = '\0';
    }

  path = ip_end + 1;

  if (boot_file)
    {
      *boot_file = grub_strdup (path);

      if (!*boot_file)
	goto cleanup;
    }

cleanup:

  if (bootfile_url)
    grub_free (bootfile_url);

  if (grub_errno)
    {
      if (proto && *proto)
	{
	  grub_free (proto);
	  *proto = NULL;
	}

      if (server_ip && *server_ip)
	{
	  grub_free (server_ip);
	  *server_ip = NULL;
	}

      if (boot_file && *boot_file)
	{
	  grub_free (boot_file);
	  *boot_file = NULL;
	}
    }

  return;
}


static grub_err_t
grub_net_configure_by_dhcpv6_adv (const struct grub_net_dhcpv6_packet *v6_adv,
	struct grub_dhcpv6_session *session)
{
  struct grub_net_buff *nb;
  const struct grub_dhcpv6_option *opt_client, *opt_server, *opt_iana;
  struct grub_dhcpv6_option *popt;
  struct grub_net_dhcpv6_packet *v6;
  struct udphdr *udph;
  grub_net_network_level_address_t multicast;
  grub_net_link_level_address_t ll_multicast;
  struct grub_net_network_level_interface *inf;
  grub_err_t err;
  grub_uint16_t len;
  grub_uint64_t elapsed;
  char err_msg[64];

  if (v6_adv->message_type != DHCPv6_ADVERTISE)
    {
      grub_error (GRUB_ERR_IO, N_("DHCPv6 info not found"));
      return grub_errno;
    }

  opt_client = find_dhcpv6_option (v6_adv, OPTION_CLIENTID);
  opt_server = find_dhcpv6_option (v6_adv, OPTION_SERVERID);
  opt_iana = find_dhcpv6_option (v6_adv, OPTION_IA_NA);

  err_msg[0] = '\0';
  if (!opt_client)
      grub_strcpy (err_msg, "client id");

  if (!opt_server)
    {
      if (grub_strlen (err_msg))
	grub_strcpy (err_msg + grub_strlen (err_msg), ", server id");
      else
	grub_strcpy (err_msg, "server id");
    }

  if (!opt_iana)
    {
      if (grub_strlen (err_msg))
	grub_strcpy (err_msg + grub_strlen (err_msg), ", iana");
      else
	grub_strcpy (err_msg, "iana");
    }

  if (grub_strlen (err_msg))
    {
      grub_strcpy (err_msg + grub_strlen (err_msg), " missing");
      grub_error (GRUB_ERR_IO, N_(err_msg));
      return grub_errno;
    }

  inf = session->ifaces;

  multicast.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV6;
  multicast.ipv6[0] = grub_cpu_to_be64_compile_time (0xff02ULL << 48);
  multicast.ipv6[1] = grub_cpu_to_be64_compile_time (0x10002ULL);

  err = grub_net_link_layer_resolve (inf, &multicast, &ll_multicast);
  if (err)
    return err;

  nb = grub_netbuff_alloc (512);

  if (!nb)
    {
      grub_netbuff_free (nb);
      return grub_errno;
    }

  err = grub_netbuff_reserve (nb, 512);
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }

  len = grub_cpu_to_be16(opt_client->len);
  err = grub_netbuff_push (nb, len + 4);
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }
  grub_memcpy (nb->data, opt_client, len + 4);

  len = grub_cpu_to_be16(opt_server->len);
  err = grub_netbuff_push (nb, len + 4);
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }
  grub_memcpy (nb->data, opt_server, len + 4);

  len = grub_cpu_to_be16(opt_iana->len);
  err = grub_netbuff_push (nb, len + 4);
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }
  grub_memcpy (nb->data, opt_iana, len + 4);

  err = grub_netbuff_push (nb, 8);
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }

  popt = (struct grub_dhcpv6_option*) nb->data;
  popt->code = grub_cpu_to_be16_compile_time (OPTION_ORO);
  popt->len = grub_cpu_to_be16_compile_time (4);
  grub_set_unaligned16 (popt->data, grub_cpu_to_be16_compile_time (OPTION_BOOTFILE_URL));
  grub_set_unaligned16 (popt->data + 2, grub_cpu_to_be16_compile_time (OPTION_DNS_SERVERS));

  err = grub_netbuff_push (nb, 6);
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }
  popt = (struct grub_dhcpv6_option*) nb->data;
  popt->code = grub_cpu_to_be16_compile_time (OPTION_ELAPSED_TIME);
  popt->len = grub_cpu_to_be16_compile_time (2);

  // the time is expressed in hundredths of a second
  elapsed = grub_divmod64 (grub_get_time_ms () - session->start_time, 10, 0);

  if (elapsed > 0xffff)
    elapsed = 0xffff;

  grub_set_unaligned16 (popt->data,  grub_cpu_to_be16 ((grub_uint16_t)elapsed));

  err = grub_netbuff_push (nb, 4);
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }

  v6 = (struct grub_net_dhcpv6_packet *) nb->data;
  v6->message_type = DHCPv6_REQUEST;
  v6->transaction_id = v6_adv->transaction_id;

  err = grub_netbuff_push (nb, sizeof (*udph));
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }

  udph = (struct udphdr *) nb->data;
  udph->src = grub_cpu_to_be16_compile_time (546);
  udph->dst = grub_cpu_to_be16_compile_time (547);
  udph->chksum = 0;
  udph->len = grub_cpu_to_be16 (nb->tail - nb->data);

  udph->chksum = grub_net_ip_transport_checksum (nb, GRUB_NET_IP_UDP,
						 &inf->address,
						 &multicast);
  err = grub_net_send_ip_packet (inf, &multicast, &ll_multicast, nb,
				 GRUB_NET_IP_UDP);

  grub_netbuff_free (nb);

  if (err)
    return err;

  return GRUB_ERR_NONE;
}


struct grub_net_network_level_interface *
grub_net_configure_by_dhcpv6_reply (const char *name,
	struct grub_net_card *card,
	grub_net_interface_flags_t flags,
	const struct grub_net_dhcpv6_packet *v6,
	grub_size_t size __attribute__ ((unused)),
	int is_def,
	char **device, char **path)
{
  grub_net_network_level_address_t addr;
  grub_net_network_level_netaddress_t netaddr;
  struct grub_net_network_level_interface *inf;
  const grub_uint8_t *your_ip;
  char *proto;
  char *server_ip;
  char *boot_file;
  grub_net_network_level_address_t *dns;
  grub_uint16_t num_dns;

  if (device)
    *device = NULL;

  if (path)
    *path = NULL;

  if (v6->message_type != DHCPv6_REPLY)
    {
      grub_error (GRUB_ERR_IO, N_("DHCPv6 info not found"));
      return NULL;
    }

  your_ip = find_dhcpv6_address(v6);

  if (!your_ip)
    {
      grub_error (GRUB_ERR_IO, N_("DHCPv6 address not found"));
      return NULL;
    }

  get_dhcpv6_dns_address (v6, &dns, &num_dns);

  if (dns && num_dns)
    {
      int i;

      for (i = 0; i < num_dns; ++i)
	grub_net_add_dns_server (dns + i);

      grub_free (dns);
    }
  else
    {
      if (grub_errno)
	grub_print_error ();
    }

  find_dhcpv6_bootfile_url (v6, &proto, &server_ip, &boot_file);

  if (grub_errno)
    grub_print_error ();

  addr.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV6;
  addr.ipv6[0] = grub_get_unaligned64 (your_ip);
  addr.ipv6[1] = grub_get_unaligned64 (your_ip + 8);
  inf = grub_net_add_addr (name, card, &addr, &card->default_address, flags);

  netaddr.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV6;
  netaddr.ipv6.base[0] = grub_get_unaligned64 (your_ip);
  netaddr.ipv6.base[1] = 0;
  netaddr.ipv6.masksize = 64;
  grub_net_add_route (name, netaddr, inf);

  grub_env_set_net_property (name, "boot_file", boot_file,
			  grub_strlen (boot_file));

  if (is_def && server_ip)
    {
      grub_net_default_server = grub_strdup (server_ip);
      grub_env_set ("net_default_interface", name);
      grub_env_export ("net_default_interface");
    }

  if (device && server_ip && proto)
    {
      *device = grub_xasprintf ("%s,%s", proto, server_ip);
      if (!*device)
	return NULL;
    }

  if (path && boot_file)
    {
      *path = grub_strdup (boot_file);
      if (*path)
	{
	  char *slash;
	  slash = grub_strrchr (*path, '/');
	  if (slash)
	    *slash = 0;
	  else
	    **path = 0;
	}
      else
	return NULL;
    }

  return inf;
}

void
grub_net_process_dhcp (struct grub_net_buff *nb,
		       struct grub_net_card *card)
{
  char *name;
  struct grub_net_network_level_interface *inf;

  name = grub_xasprintf ("%s:dhcp", card->name);
  if (!name)
    {
      grub_print_error ();
      return;
    }
  grub_net_configure_by_dhcp_ack (name, card,
				  0, (const struct grub_net_bootp_packet *) nb->data,
				  (nb->tail - nb->data), 0, 0, 0);
  grub_free (name);
  if (grub_errno)
    grub_print_error ();
  else
    {
      FOR_NET_NETWORK_LEVEL_INTERFACES(inf)
	if (grub_memcmp (inf->name, card->name, grub_strlen (card->name)) == 0
	    && grub_memcmp (inf->name + grub_strlen (card->name),
			    ":dhcp_tmp", sizeof (":dhcp_tmp") - 1) == 0)
	  {
	    grub_net_network_level_interface_unregister (inf);
	    break;
	  }
    }
}

void
grub_net_process_dhcp6 (struct grub_net_buff *nb,
	struct grub_net_card *card __attribute__ ((unused)))
{
  const struct grub_net_dhcpv6_packet *v6;
  struct grub_dhcpv6_session *session;
  const struct grub_dhcpv6_option *opt_iana;
  const struct grub_dhcpv6_iana_option *ia_na;

  v6 = (const struct grub_net_dhcpv6_packet *) nb->data;

  opt_iana = find_dhcpv6_option (v6, OPTION_IA_NA);
  if (!opt_iana)
    return;

  ia_na = (const struct grub_dhcpv6_iana_option *)opt_iana->data;
  FOR_DHCPV6_SESSIONS (session)
    {
      if (session->transaction_id == v6->transaction_id
	  && session->iaid == grub_cpu_to_be32 (ia_na->iaid))
	break;
    }

  if (!session)
    return;


  if (v6->message_type == DHCPv6_ADVERTISE)
    {
      grub_net_configure_by_dhcpv6_adv (
	  (const struct grub_net_dhcpv6_packet*) nb->data, session);
    }
  else if (v6->message_type == DHCPv6_REPLY)
    {
      char *name;
      struct grub_net_network_level_interface *inf;

      inf = session->ifaces;
      name = grub_xasprintf ("%s:dhcp", inf->card->name);
      if (!name)
	return;

      grub_net_configure_by_dhcpv6_reply (name, inf->card,
	  0, (const struct grub_net_dhcpv6_packet *) nb->data,
	  (nb->tail - nb->data), 0, 0, 0);

      if (!grub_errno)
	{
	  grub_dhcpv6_session_remove (session);
	  grub_free (session);
	}

      grub_free (name);
    }

  if (grub_errno)
    grub_print_error ();

  return;
}

static char
hexdigit (grub_uint8_t val)
{
  if (val < 10)
    return val + '0';
  return val + 'a' - 10;
}

static grub_err_t
grub_cmd_dhcpopt (struct grub_command *cmd __attribute__ ((unused)),
		  int argc, char **args)
{
  struct grub_net_network_level_interface *inter;
  int num;
  grub_uint8_t *ptr;
  grub_uint8_t taglength;

  if (argc < 4)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("four arguments expected"));

  FOR_NET_NETWORK_LEVEL_INTERFACES (inter)
    if (grub_strcmp (inter->name, args[1]) == 0)
      break;

  if (!inter)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("unrecognised network interface `%s'"), args[1]);

  if (!inter->dhcp_ack)
    return grub_error (GRUB_ERR_IO, N_("no DHCP info found"));

  if (inter->dhcp_acklen <= OFFSET_OF (vendor, inter->dhcp_ack))
    return grub_error (GRUB_ERR_IO, N_("no DHCP options found"));

  num = grub_strtoul (args[2], 0, 0);
  if (grub_errno)
    return grub_errno;

  ptr = inter->dhcp_ack->vendor;

  if (ptr[0] != GRUB_NET_BOOTP_RFC1048_MAGIC_0
      || ptr[1] != GRUB_NET_BOOTP_RFC1048_MAGIC_1
      || ptr[2] != GRUB_NET_BOOTP_RFC1048_MAGIC_2
      || ptr[3] != GRUB_NET_BOOTP_RFC1048_MAGIC_3)
    return grub_error (GRUB_ERR_IO, N_("no DHCP options found"));
  ptr = ptr + sizeof (grub_uint32_t);
  while (1)
    {
      grub_uint8_t tagtype;

      if (ptr >= ((grub_uint8_t *) inter->dhcp_ack) + inter->dhcp_acklen)
	return grub_error (GRUB_ERR_IO, N_("no DHCP option %d found"), num);

      tagtype = *ptr++;

      /* Pad tag.  */
      if (tagtype == 0)
	continue;

      /* End tag.  */
      if (tagtype == 0xff)
	return grub_error (GRUB_ERR_IO, N_("no DHCP option %d found"), num);

      taglength = *ptr++;
	
      if (tagtype == num)
	break;
      ptr += taglength;
    }

  if (grub_strcmp (args[3], "string") == 0)
    {
      char *val = grub_malloc (taglength + 1);
      if (!val)
	return grub_errno;
      grub_memcpy (val, ptr, taglength);
      val[taglength] = 0;
      if (args[0][0] == '-' && args[0][1] == 0)
	grub_printf ("%s\n", val);
      else
	return grub_env_set (args[0], val);
      return GRUB_ERR_NONE;
    }

  if (grub_strcmp (args[3], "number") == 0)
    {
      grub_uint64_t val = 0;
      int i;
      for (i = 0; i < taglength; i++)
	val = (val << 8) | ptr[i];
      if (args[0][0] == '-' && args[0][1] == 0)
	grub_printf ("%llu\n", (unsigned long long) val);
      else
	{
	  char valn[64];
	  grub_snprintf (valn, sizeof (valn), "%lld\n", (unsigned long long) val);
	  return grub_env_set (args[0], valn);
	}
      return GRUB_ERR_NONE;
    }

  if (grub_strcmp (args[3], "hex") == 0)
    {
      char *val = grub_malloc (2 * taglength + 1);
      int i;
      if (!val)
	return grub_errno;
      for (i = 0; i < taglength; i++)
	{
	  val[2 * i] = hexdigit (ptr[i] >> 4);
	  val[2 * i + 1] = hexdigit (ptr[i] & 0xf);
	}
      val[2 * taglength] = 0;
      if (args[0][0] == '-' && args[0][1] == 0)
	grub_printf ("%s\n", val);
      else
	return grub_env_set (args[0], val);
      return GRUB_ERR_NONE;
    }

  return grub_error (GRUB_ERR_BAD_ARGUMENT,
		     N_("unrecognised DHCP option format specification `%s'"),
		     args[3]);
}

/* FIXME: allow to specify mac address.  */
static grub_err_t
grub_cmd_bootp (struct grub_command *cmd __attribute__ ((unused)),
		int argc, char **args)
{
  struct grub_net_card *card;
  struct grub_net_network_level_interface *ifaces;
  grub_size_t ncards = 0;
  unsigned j = 0;
  int interval;
  grub_err_t err;

  FOR_NET_CARDS (card)
  {
    if (argc > 0 && grub_strcmp (card->name, args[0]) != 0)
      continue;
    ncards++;
  }

  if (ncards == 0)
    return grub_error (GRUB_ERR_NET_NO_CARD, N_("no network card found"));

  ifaces = grub_zalloc (ncards * sizeof (ifaces[0]));
  if (!ifaces)
    return grub_errno;

  j = 0;
  FOR_NET_CARDS (card)
  {
    if (argc > 0 && grub_strcmp (card->name, args[0]) != 0)
      continue;
    ifaces[j].card = card;
    ifaces[j].next = &ifaces[j+1];
    if (j)
      ifaces[j].prev = &ifaces[j-1].next;
    ifaces[j].name = grub_xasprintf ("%s:dhcp_tmp", card->name);
    card->num_ifaces++;
    if (!ifaces[j].name)
      {
	unsigned i;
	for (i = 0; i < j; i++)
	  grub_free (ifaces[i].name);
	grub_free (ifaces);
	return grub_errno;
      }
    ifaces[j].address.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_DHCP_RECV;
    grub_memcpy (&ifaces[j].hwaddress, &card->default_address, 
		 sizeof (ifaces[j].hwaddress));
    j++;
  }
  ifaces[ncards - 1].next = grub_net_network_level_interfaces;
  if (grub_net_network_level_interfaces)
    grub_net_network_level_interfaces->prev = & ifaces[ncards - 1].next;
  grub_net_network_level_interfaces = &ifaces[0];
  ifaces[0].prev = &grub_net_network_level_interfaces;
  for (interval = 200; interval < 10000; interval *= 2)
    {
      int done = 0;
      for (j = 0; j < ncards; j++)
	{
	  struct grub_net_bootp_packet *pack;
	  struct grub_datetime date;
	  grub_int32_t t = 0;
	  struct grub_net_buff *nb;
	  struct udphdr *udph;
	  grub_net_network_level_address_t target;
	  grub_net_link_level_address_t ll_target;

	  if (!ifaces[j].prev)
	    continue;
	  nb = grub_netbuff_alloc (sizeof (*pack) + 64 + 128);
	  if (!nb)
	    {
	      grub_netbuff_free (nb);
	      return grub_errno;
	    }
	  err = grub_netbuff_reserve (nb, sizeof (*pack) + 64 + 128);
	  if (err)
	    {
	      grub_netbuff_free (nb);
	      return err;
	    }
	  err = grub_netbuff_push (nb, sizeof (*pack) + 64);
	  if (err)
	    {
	      grub_netbuff_free (nb);
	      return err;
	    }
	  pack = (void *) nb->data;
	  done = 1;
	  grub_memset (pack, 0, sizeof (*pack) + 64);
	  pack->opcode = 1;
	  pack->hw_type = 1;
	  pack->hw_len = 6;
	  err = grub_get_datetime (&date);
	  if (err || !grub_datetime2unixtime (&date, &t))
	    {
	      grub_errno = GRUB_ERR_NONE;
	      t = 0;
	    }
	  pack->ident = grub_cpu_to_be32 (t);
	  pack->seconds = grub_cpu_to_be16 (t);

	  grub_memcpy (&pack->mac_addr, &ifaces[j].hwaddress.mac, 6); 

	  grub_netbuff_push (nb, sizeof (*udph));

	  udph = (struct udphdr *) nb->data;
	  udph->src = grub_cpu_to_be16_compile_time (68);
	  udph->dst = grub_cpu_to_be16_compile_time (67);
	  udph->chksum = 0;
	  udph->len = grub_cpu_to_be16 (nb->tail - nb->data);
	  target.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
	  target.ipv4 = 0xffffffff;
	  err = grub_net_link_layer_resolve (&ifaces[j], &target, &ll_target);
	  if (err)
	    return err;

	  udph->chksum = grub_net_ip_transport_checksum (nb, GRUB_NET_IP_UDP,
							 &ifaces[j].address,
							 &target);

	  err = grub_net_send_ip_packet (&ifaces[j], &target, &ll_target, nb,
					 GRUB_NET_IP_UDP);
	  grub_netbuff_free (nb);
	  if (err)
	    return err;
	}
      if (!done)
	break;
      grub_net_poll_cards (interval, 0);
    }

  err = GRUB_ERR_NONE;
  for (j = 0; j < ncards; j++)
    {
      grub_free (ifaces[j].name);
      if (!ifaces[j].prev)
	continue;
      grub_error_push ();
      grub_net_network_level_interface_unregister (&ifaces[j]);
      err = grub_error (GRUB_ERR_FILE_NOT_FOUND,
			N_("couldn't autoconfigure %s"),
			ifaces[j].card->name);
    }

  grub_free (ifaces);
  return err;
}

static grub_err_t
grub_cmd_bootp6 (struct grub_command *cmd __attribute__ ((unused)),
	int argc, char **args)
{
  struct grub_net_card *card;
  grub_size_t ncards = 0;
  unsigned j = 0;
  int interval;
  grub_err_t err;
  struct grub_dhcpv6_session *session;

  err = GRUB_ERR_NONE;

  FOR_NET_CARDS (card)
  {
    if (argc > 0 && grub_strcmp (card->name, args[0]) != 0)
      continue;
#ifdef GRUB_MACHINE_EFI
    else if (!card->is_efi_mac_device (card))
      continue;
#endif
    ncards++;
  }

  FOR_NET_CARDS (card)
  {
    struct grub_net_network_level_interface *ifaces;

    if (argc > 0 && grub_strcmp (card->name, args[0]) != 0)
      continue;
#ifdef GRUB_MACHINE_EFI
    else if (!card->is_efi_mac_device (card))
      continue;
#endif

    ifaces = grub_net_ipv6_get_link_local (card, &card->default_address);
    if (!ifaces)
      {
	grub_free (ifaces);
	return grub_errno;
      }

    session = grub_zalloc (sizeof (*session));
    session->ifaces = ifaces;
    session->iaid = j;
    grub_dhcpv6_session_add (session);
    j++;
  }

  for (interval = 200; interval < 10000; interval *= 2)
    {
      int done = 1;

      FOR_DHCPV6_SESSIONS (session)
	{
	  struct grub_net_buff *nb;
	  struct grub_dhcpv6_option *opt;
	  struct grub_net_dhcpv6_packet *v6;
	  struct grub_DUID_LL *duid;
	  struct grub_dhcpv6_iana_option *ia_na;
	  grub_net_network_level_address_t multicast;
	  grub_net_link_level_address_t ll_multicast;
	  struct udphdr *udph;

	  multicast.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV6;
	  multicast.ipv6[0] = grub_cpu_to_be64_compile_time (0xff02ULL << 48);
	  multicast.ipv6[1] = grub_cpu_to_be64_compile_time (0x10002ULL);

	  err = grub_net_link_layer_resolve (session->ifaces,
		    &multicast, &ll_multicast);
	  if (err)
	    return grub_errno;
	  nb = grub_netbuff_alloc (512);
	  if (!nb)
	    {
	      grub_netbuff_free (nb);
	      return grub_errno;
	    }

	  err = grub_netbuff_reserve (nb, 512);
	  if (err)
	    {
	      grub_netbuff_free (nb);
	      return err;
	    }

	  err = grub_netbuff_push (nb, 6);
	  if (err)
	    {
	      grub_netbuff_free (nb);
	      return err;
	    }

	  opt = (struct grub_dhcpv6_option *)nb->data;
	  opt->code = grub_cpu_to_be16_compile_time (OPTION_ELAPSED_TIME);
	  opt->len = grub_cpu_to_be16_compile_time (2);
	  grub_set_unaligned16 (opt->data, 0);

	  err = grub_netbuff_push (nb, sizeof(*duid) + 4);
	  if (err)
	    {
	      grub_netbuff_free (nb);
	      return err;
	    }

	  opt = (struct grub_dhcpv6_option *)nb->data;
	  opt->code = grub_cpu_to_be16_compile_time (OPTION_CLIENTID); //option_client_id
	  opt->len = grub_cpu_to_be16 (sizeof(*duid));

	  duid = (struct grub_DUID_LL *) opt->data;

	  duid->type = grub_cpu_to_be16_compile_time (3) ;
	  duid->hw_type = grub_cpu_to_be16_compile_time (1);
	  grub_memcpy (&duid->hwaddr, &session->ifaces->hwaddress.mac,
	      sizeof (session->ifaces->hwaddress.mac));

	  err = grub_netbuff_push (nb, sizeof (*ia_na) + 4);
	  if (err)
	    {
	      grub_netbuff_free (nb);
	      return err;
	    }

	  opt = (struct grub_dhcpv6_option *)nb->data;
	  opt->code = grub_cpu_to_be16_compile_time (OPTION_IA_NA);
	  opt->len = grub_cpu_to_be16 (sizeof (*ia_na));
	  ia_na = (struct grub_dhcpv6_iana_option *)opt->data;
	  ia_na->iaid = grub_cpu_to_be32 (session->iaid);
	  ia_na->t1 = 0;
	  ia_na->t2 = 0;

	  err = grub_netbuff_push (nb, 4);
	  if (err)
	    {
	      grub_netbuff_free (nb);
	      return err;
	    }

	  v6 = (struct grub_net_dhcpv6_packet *)nb->data;
	  v6->message_type = 1;
	  v6->transaction_id = session->transaction_id;

	  grub_netbuff_push (nb, sizeof (*udph));

	  udph = (struct udphdr *) nb->data;
	  udph->src = grub_cpu_to_be16_compile_time (546);
	  udph->dst = grub_cpu_to_be16_compile_time (547);
	  udph->chksum = 0;
	  udph->len = grub_cpu_to_be16 (nb->tail - nb->data);

	  udph->chksum = grub_net_ip_transport_checksum (nb, GRUB_NET_IP_UDP,
			    &session->ifaces->address, &multicast);

	  err = grub_net_send_ip_packet (session->ifaces, &multicast,
		    &ll_multicast, nb, GRUB_NET_IP_UDP);
	  done = 0;
	  grub_netbuff_free (nb);

	  if (err)
	    return err;
	}
      if (!done)
	grub_net_poll_cards (interval, 0);
    }

  FOR_DHCPV6_SESSIONS (session)
    {
      err = grub_error (GRUB_ERR_FILE_NOT_FOUND,
			N_("couldn't autoconfigure %s"),
			session->ifaces->card->name);
      grub_dhcpv6_session_remove (session);
      grub_free (session);
    }


  return err;
}

static grub_command_t cmd_getdhcp, cmd_bootp, cmd_bootp6;

void
grub_bootp_init (void)
{
  cmd_bootp = grub_register_command ("net_bootp", grub_cmd_bootp,
				     N_("[CARD]"),
				     N_("perform a bootp autoconfiguration"));
  cmd_getdhcp = grub_register_command ("net_get_dhcp_option", grub_cmd_dhcpopt,
				       N_("VAR INTERFACE NUMBER DESCRIPTION"),
				       N_("retrieve DHCP option and save it into VAR. If VAR is - then print the value."));
  cmd_bootp6 = grub_register_command ("net_bootp6", grub_cmd_bootp6,
				     N_("[CARD]"),
				     N_("perform a dhcpv6 autoconfiguration"));
}

void
grub_bootp_fini (void)
{
  grub_unregister_command (cmd_getdhcp);
  grub_unregister_command (cmd_bootp);
  grub_unregister_command (cmd_bootp6);
}
