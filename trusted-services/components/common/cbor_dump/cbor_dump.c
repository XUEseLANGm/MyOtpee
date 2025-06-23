/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <string.h>
#include <qcbor/qcbor_decode.h>
#include "cbor_dump.h"

/* Dump context structure */
struct dump_context
{
    FILE *outfile;
    unsigned int initial_indent;
    const char *root_label;
    const struct cbor_dictionary_entry *dictionary;
    unsigned int dictionary_len;
};

static int dump_next_item(QCBORDecodeContext *decode_ctx, struct dump_context *dump_ctx);
static void dump_indent(struct dump_context *dump_ctx, const QCBORItem *item);
static void dump_label(struct dump_context *dump_ctx, const QCBORItem *item);
static void dump_value_separator(struct dump_context *dump_ctx, const QCBORItem *item);
static void dump_value(struct dump_context *dump_ctx, const QCBORItem *item);
static void dump_text_string(struct dump_context *dump_ctx, const char *data, size_t len);
static void dump_byte_string(struct dump_context *dump_ctx, const uint8_t *data, size_t len);
static const char *dictionary_lookup(struct dump_context *dump_ctx, int64_t id);

int cbor_dump(FILE *file,
    const uint8_t *cbor, size_t cbor_len,
    unsigned int indent, const char *root_label,
    const struct cbor_dictionary_entry *dictionary, unsigned int dictionary_len)
{
    int status = -1;
    UsefulBufC cbor_buf;
    UsefulBuf mem_pool;
    uint8_t mem_pool_space[cbor_len + QCBOR_DECODE_MIN_MEM_POOL_SIZE];

    cbor_buf.ptr = cbor;
    cbor_buf.len = cbor_len;

    mem_pool.ptr = mem_pool_space;
    mem_pool.len = sizeof(mem_pool_space);

    QCBORDecodeContext decode_ctx;

    QCBORDecode_Init(&decode_ctx, cbor_buf, QCBOR_DECODE_MODE_NORMAL);
    status = QCBORDecode_SetMemPool(&decode_ctx, mem_pool, true);

    if (status == QCBOR_SUCCESS) {

        struct dump_context dump_ctx;

        dump_ctx.outfile = file;
        dump_ctx.initial_indent = indent;
        dump_ctx.root_label = root_label;
        dump_ctx.dictionary = dictionary;
        dump_ctx.dictionary_len = dictionary_len;

        while ((status = dump_next_item(&decode_ctx, &dump_ctx)) == QCBOR_SUCCESS);

        // Hitting the end of data is not an error.
        if (status == QCBOR_ERR_NO_MORE_ITEMS)
        	status=QCBOR_SUCCESS;
    }

    return status;
}

static int dump_next_item(QCBORDecodeContext *decode_ctx, struct dump_context *dump_ctx)
{
    int status = -1;
    QCBORItem item;

    status = QCBORDecode_GetNext(decode_ctx, &item);

    if (status == QCBOR_SUCCESS) {

        dump_indent(dump_ctx, &item);
        dump_label(dump_ctx, &item);
        dump_value_separator(dump_ctx, &item);
        dump_value(dump_ctx, &item);
    }

    return status;
}

static void dump_indent(struct dump_context *dump_ctx, const QCBORItem *item)
{
    unsigned int num_tabs = dump_ctx->initial_indent + item->uNestingLevel;

    for (unsigned int i = 0; i < num_tabs; ++i) {

        fprintf(dump_ctx->outfile, "    ");
    }
}

static void dump_label(struct dump_context *dump_ctx, const QCBORItem *item)
{
    switch (item->uLabelType)
    {
        case QCBOR_TYPE_INT64:
        case QCBOR_TYPE_UINT64:
        {
            const char *label_string = dictionary_lookup(dump_ctx, item->label.int64);
            if (label_string)
                fprintf(dump_ctx->outfile, "%s:", label_string);
            else
                fprintf(dump_ctx->outfile, "%ld:", item->label.int64);
            break;
        }
        case QCBOR_TYPE_TEXT_STRING:
            fprintf(dump_ctx->outfile, "%s:", (const char*)item->label.string.ptr);
            break;
        case QCBOR_TYPE_NONE:
            if (item->uNestingLevel == 0 && dump_ctx->root_label) {
                fprintf(dump_ctx->outfile, "%s:", dump_ctx->root_label);
            }
            break;
        default:
            break;
    }
}

static void dump_value_separator(struct dump_context *dump_ctx, const QCBORItem *item)
{
    if ((item->uDataType == QCBOR_TYPE_ARRAY) ||
        (item->uDataType == QCBOR_TYPE_MAP)) {

        fprintf(dump_ctx->outfile, "\n");
    }
    else {

        fprintf(dump_ctx->outfile, "\t");
    }

}

static void dump_value(struct dump_context *dump_ctx, const QCBORItem *item)
{
    if (item->uDataType == QCBOR_TYPE_TEXT_STRING) {

        dump_text_string(dump_ctx, (const char*)item->val.string.ptr, item->val.string.len);
        fprintf(dump_ctx->outfile, "\n");
    }
    else if (item->uDataType == QCBOR_TYPE_BYTE_STRING) {

        dump_byte_string(dump_ctx, (const uint8_t*)item->val.string.ptr, item->val.string.len);
        fprintf(dump_ctx->outfile, "\n");
    }
    else if (item->uDataType == QCBOR_TYPE_INT64) {

        fprintf(dump_ctx->outfile, "%ld\n", item->val.int64);
    }
    else if (item->uDataType == QCBOR_TYPE_UINT64) {

        fprintf(dump_ctx->outfile, "%lu\n", item->val.uint64);
    }
    else if ((item->uDataType != QCBOR_TYPE_NONE) &&
        (item->uDataType != QCBOR_TYPE_ARRAY) &&
        (item->uDataType != QCBOR_TYPE_MAP))
    {

        fprintf(dump_ctx->outfile, "value %d", item->uDataType);
    }
}

static void dump_text_string(struct dump_context *dump_ctx, const char *data, size_t len)
{
    char text_buf[len + 1];

    memcpy(text_buf, data, len);
    text_buf[len] = '\0';

    fprintf(dump_ctx->outfile, "%s", text_buf);
}

static void dump_byte_string(struct dump_context *dump_ctx, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {

        fprintf(dump_ctx->outfile, "%02x ", data[i]);
    }
}

static const char *dictionary_lookup(struct dump_context *dump_ctx, int64_t id)
{
    const char *match = NULL;

    if (dump_ctx->dictionary) {

        for (size_t i = 0; i < dump_ctx->dictionary_len; ++i) {

            if (dump_ctx->dictionary[i].id == id) {

                match = dump_ctx->dictionary[i].string;
                break;
            }
        }
    }

    return match;
}
