/* ewvdb loader
 * this loader loads SFAM's vdb file
 */

#include "../idaldr.h"
#include <typeinf.hpp>
#include <pro.h>
#include "rc4_wrap.h"

#define EWVDB_MAGIC 0x44565745

struct vdb_header {
	unsigned int db_signature;
	unsigned int checksum;
	unsigned int sig_num;
	unsigned int date_released;
	unsigned int db_size;
	unsigned int vdb_version;
};

struct vdb_signature {
	unsigned int is_false_pstv;
	unsigned int mal_type;
	unsigned int offset_type;
	unsigned int offset;
	unsigned int has_wild_cards;
	unsigned int sig_len;
	unsigned int header_len;
	unsigned int sig_pointer;
	unsigned int name_pointer;
	unsigned int header_pointer;
	unsigned int eng_file_ptr;
	unsigned int eng_size;
};

/* check input file format. If recognized, return 1
 * and fill 'fileformatname' otherwise return 0
 */
static int idaapi accept_ewvdb(linput_t *li, 
		char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
	uint32 magic;
	/* read as much of the file as you need to to determine whether
	 * it is something that you recognize */
	if(n || lread4bytes(li, &magic, false)) //read as little endian by default
		return 0;
	if (magic != EWVDB_MAGIC)
		return 0;
	/* if you recognize the file, then say so */
	qstrncpy(fileformatname, "ewvdb Format", MAX_FILE_FORMAT_NAME);
	return 1;
}

const char *ewvdb_types =
	"struct vdb_header {\n"
		"unsigned int db_signature;\n"
		"unsigned int checksum;\n"
		"unsigned int sig_num;\n"
		"unsigned int date_released;\n"
		"unsigned int db_size;\n"
		"unsigned int vdb_version;\n"
	"};\n"
	"struct vdb_signature {\n"
		"unsigned int is_false_pstv;\n"
		"unsigned int mal_type;\n"
		"unsigned int offset_type;\n"
		"unsigned int offset;\n"
		"unsigned int has_wild_cards;\n"
		"unsigned int sig_len;\n"
		"unsigned int header_len;\n"
		"unsigned int sig_pointer;\n"
		"unsigned int name_pointer;\n"
		"unsigned int header_pointer;\n"
		"unsigned int eng_file_ptr;\n"
		"unsigned int eng_size;\n"
	"};\n";

void add_types(tid_t *vdb_hdr_tid, tid_t *vdb_sig_tid)
{
	til_t *tmp_til;
	tmp_til = new_til("ewvdb.til", "ewvdb header types");	/* type name, descs */
	parse_decls(tmp_til, ewvdb_types, msg, HTI_PAK1);	/* til, input_string, printer_cb, hti_flags */
	sort_til(tmp_til); 					/* til should be sorted after operation */
	*vdb_hdr_tid = import_type(tmp_til, -1, "vdb_header");
	*vdb_sig_tid = import_type(tmp_til, -1, "vdb_signature");
	free_til(tmp_til);					/* free our temp til */
}

static void gen_eng_name(uint32 index, char *name, size_t buf_size)
{
	qsnprintf(name, buf_size, "dis_eng_%d", index);
}

static size_t lsize(linput_t *li)
{
	int32 pos_backup;
	size_t size;
	pos_backup = qltell(li);
	size = (size_t)qlseek(li, 0, SEEK_END);
	/* return the fpointer back to it's original value */
	qlseek(li, pos_backup, SEEK_SET);
	return size;
}

static void vdb_decrypt(void *dest, const void *src, size_t size)
{
	wchar_t *key = L"AKSGA";
	rc4_crypt((uchar *)key, wcslen(key) * sizeof(wchar_t), (uchar *)src, (uchar *)dest, size);
}

static int load_vdb2mem(linput_t *li, void **vdb_map)
{
	size_t vdb_size;
	void *buf;
	struct vdb_header *vhdr;
	uint32 db_size;
	void *sigs;

	vdb_size = lsize(li);
	if (!(buf = qalloc(vdb_size)))
		return 0;
	lread(li, buf, vdb_size);
	vhdr = (struct vdb_header *)buf;
	db_size = vhdr->db_size;
	sigs = (void *)(vhdr + 1);
	/* decrypt the signatures */
	vdb_decrypt(sigs, sigs, db_size);
	*vdb_map = buf;
	return 1;
}

static void idaapi load_ewvdb(linput_t *li, ushort neflags, const char * /*fileformatname*/)
{
	tid_t vdb_hdr_tid, vdb_sig_tid;
	void *vdb_map;
	struct vdb_header *vhdr;
	struct vdb_signature *vsig;
	ea_t pos, sig_base, eng_pos, eng_base;

	if (!load_vdb2mem(li, &vdb_map))
		loader_failure();
	
	create_filename_cmt();
	add_types(&vdb_hdr_tid, &vdb_sig_tid);

	vhdr = (struct vdb_header *)vdb_map;
	/* dump the file header to database */
	mem2base(vhdr, 0, sizeof(vdb_header), 0);
	/* add new code segment for the header */
	if (!add_segm(0, 0, sizeof(vdb_header), ".vdb_header", CLASS_DATA))
		goto loader_error;
	/* annotate the header struct 
	 * (note: segment creation destroys previous annotations) */
	doStruct(0, sizeof(vdb_header), vdb_hdr_tid);

	/* dump the signature structures */
	vsig = (struct vdb_signature *)(vhdr + 1);
	sig_base = (ea_t)((char *)vsig - (char *)vhdr);
	pos = sig_base;
	for (uint32 i = 0; i < vhdr->sig_num; i++) {
		mem2base(&vsig[i], pos, pos + sizeof(vdb_signature), pos); 
		pos += sizeof(vdb_signature);
	}
	/* add new code segment for the signatures */
	if (!add_segm(0, sig_base, pos, ".vdb_sigs", CLASS_DATA))
		goto loader_error;
	eng_base = pos;
	eng_pos = eng_base;
	pos = sig_base;
	for (uint32 i = 0; i < vhdr->sig_num; i++) {
		char sig_name[20];
		/* annotate the signature structures */
		doStruct(pos, sizeof(vdb_signature), vdb_sig_tid);
		/* set the signature name */
		qsnprintf(sig_name, sizeof(sig_name), "sig_%d", i);
		set_name(pos, sig_name, SN_PUBLIC);
		/* dump the disinfection engines */
		if (vsig[i].eng_file_ptr) {
			char eng_name[20];

			/* generate engine name */
			gen_eng_name(i, eng_name, sizeof(eng_name));
			set_cmt(pos, eng_name, false);
			
			/* dump disinfection engine */
			mem2base((void *)((char *)vsig + vsig[i].eng_file_ptr), 
				eng_pos, eng_pos + vsig[i].eng_size, -1);
			/* mark it to be disassembled */
			add_entry(eng_pos, eng_pos, eng_name, true);
			eng_pos += vsig[i].eng_size;
		}
		pos += sizeof(vdb_signature);
	}
	if (!add_segm(0, eng_base, eng_pos, ".dis_engines", CLASS_CODE))
		goto loader_error;
	qfree(vdb_map);
	return;
loader_error:
	qfree(vdb_map);
	loader_failure();
}

/* LOADER DESCRIPTION BLOCK */
loader_t LDSC = {
	IDP_INTERFACE_VERSION,
	0,			/* loader flags */
	accept_ewvdb,
	load_ewvdb,
	/* create output file from the database */
	NULL,
	/* take care of moved segment (fix up relocations, for example) */
	NULL,
	/* initialize user configurable options based on the input file */
	NULL,
};