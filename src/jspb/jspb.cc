//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "jspb/jspb.h"
#include <string>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/repeated_field.h>
#include <stdio.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/error/error.h>
#include <rapidjson/error/en.h>
#include "base64/base64.h"
//! ----------------------------------------------------------------------------
//! Macros
//! ----------------------------------------------------------------------------
#ifndef JSPB_TRACE
#define JSPB_TRACE(...) \
  if(s_trace) { \
    fprintf(stdout, "%s:%s.%d: ", __FILE__, __FUNCTION__, __LINE__); \
    fprintf(stdout, __VA_ARGS__); \
    fflush(stdout); \
  }
#endif
#define JSPB_ERR_LEN 4096
#define JSPB_PERROR(...) do { \
  if(s_trace) { \
    fprintf(stdout, "%s:%s.%d: ERROR ", __FILE__, __FUNCTION__, __LINE__); \
    fprintf(stdout, __VA_ARGS__);               \
    fprintf(stdout, "\n");\
    fflush(stdout); \
  }\
  snprintf(s_err_msg, JSPB_ERR_LEN, __VA_ARGS__); \
}while(0)
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! Globals
//! ----------------------------------------------------------------------------
static bool s_trace;
static char s_err_msg[JSPB_ERR_LEN];
//! ----------------------------------------------------------------------------
//! \details: Set a single field value in the json object.
//! \return:  TODO
//! \param:   reflection the protobuf message reflection informationm
//! \param:   field the protobuf message field information
//! \param:   message the protobuf message to read from
//! \param:   value the json object to update
//! ----------------------------------------------------------------------------
static int32_t convert_single_field(rapidjson::Value &ao_val,
                                    rapidjson::Document::AllocatorType& a_alx,
                                    const google::protobuf::Reflection* a_ref,
                                    const google::protobuf::FieldDescriptor* a_field,
                                    const google::protobuf::Message& a_msg)
{
        switch (a_field->type())
        {
        case google::protobuf::FieldDescriptor::TYPE_DOUBLE:
        {
                ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(),
                                 a_ref->GetDouble(a_msg, a_field),
                                 a_alx);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_FLOAT:
        {
                ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(),
                                 a_ref->GetFloat(a_msg, a_field),
                                 a_alx);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_INT64:
        case google::protobuf::FieldDescriptor::TYPE_SFIXED64:
        case google::protobuf::FieldDescriptor::TYPE_SINT64:
        {
                ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(),
                                 a_ref->GetInt64(a_msg, a_field),
                                 a_alx);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_UINT64:
        case google::protobuf::FieldDescriptor::TYPE_FIXED64:
        {
                ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(),
                                 a_ref->GetUInt64(a_msg, a_field),
                                 a_alx);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_INT32:
        case google::protobuf::FieldDescriptor::TYPE_SFIXED32:
        case google::protobuf::FieldDescriptor::TYPE_SINT32:
        {
                ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(),
                                 a_ref->GetInt32(a_msg, a_field),
                                 a_alx);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_FIXED32:
        case google::protobuf::FieldDescriptor::TYPE_UINT32:
        {
                ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(),
                                 a_ref->GetUInt32(a_msg, a_field),
                                 a_alx);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_BOOL:
        {
                ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(),
                                 a_ref->GetBool(a_msg, a_field),
                                 a_alx);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_STRING:
        {
                const std::string &l_ref = a_ref->GetString(a_msg, a_field);
                ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(),
                                 rapidjson::Value(l_ref.data(), l_ref.length(), a_alx).Move(),
                                 a_alx);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_GROUP:
        {
                JSPB_PERROR("group type not supported for field: '%s'", a_field->full_name().c_str());
                return JSPB_ERROR;
        }
        case google::protobuf::FieldDescriptor::TYPE_MESSAGE:
        {
                rapidjson::Value l_obj;
                l_obj.SetObject();
                int32_t l_s;
                l_s = convert_to_json(l_obj, a_alx, a_ref->GetMessage(a_msg, a_field));
                if(l_s != JSPB_OK)
                {
                        return JSPB_ERROR;
                }
                ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(),
                                 l_obj,
                                 a_alx);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_BYTES:
        {
                std::string l_str = a_ref->GetString(a_msg, a_field);
                std::string l_b64_str = base64_encode((unsigned char*)l_str.c_str(), l_str.length());
                ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(),
                                 rapidjson::Value(l_b64_str.data(), l_b64_str.length(), a_alx).Move(),
                                 a_alx);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_ENUM:
        {
                ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(),
                                 rapidjson::Value(a_ref->GetEnum(a_msg, a_field)->name().c_str(), a_alx).Move(),
                                 a_alx);
                break;
        }
        default:
        {
                JSPB_PERROR("unknown type in field: '%s' type: %d", a_field->full_name().c_str(), a_field->type());
                return JSPB_ERROR;
        }
        }
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Convert a repeated field to json for various types.
//! \return:  TODO
//! \param:   reflection the reflection interface for the message
//! \param:   converter the member function to do the conversion
//! \param:   field the field descriptor for the field we are converting
//! \param:   message the message being converted
//! \param:   value the value to store the converted data
//! ----------------------------------------------------------------------------
template <typename T, typename F1>
static int32_t convert_repeated_field(rapidjson::Value &ao_val,
                                      rapidjson::Document::AllocatorType& a_alx,
                                      const google::protobuf::Reflection* a_ref,
                                      F1 converter,
                                      const google::protobuf::FieldDescriptor* a_field,
                                      const google::protobuf::Message& a_msg)
{
        // Add array object...
        rapidjson::Value l_arr(rapidjson::kArrayType);
        for (int i_f = 0; i_f < a_ref->FieldSize(a_msg, a_field); ++i_f)
        {
                l_arr.PushBack(rapidjson::Value((T)(a_ref->*converter)(a_msg, a_field, i_f)).Move(),
                               a_alx);
        }
        ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(), l_arr, a_alx);
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Convert a repeated field to json for various types.
//! \return:  TODO
//! \param:   reflection the reflection interface for the message
//! \param:   converter the member function to do the conversion
//! \param:   field the field descriptor for the field we are converting
//! \param:   message the message being converted
//! \param:   value the value to store the converted data
//! ----------------------------------------------------------------------------
template <typename F1>
static int32_t convert_repeated_field_str(rapidjson::Value &ao_val,
                                          rapidjson::Document::AllocatorType& a_alx,
                                          const google::protobuf::Reflection* a_ref,
                                          F1 converter,
                                          const google::protobuf::FieldDescriptor* a_field,
                                          const google::protobuf::Message& a_msg)
{
        // Add array object...
        rapidjson::Value l_arr(rapidjson::kArrayType);
        for (int i_f = 0; i_f < a_ref->FieldSize(a_msg, a_field); ++i_f)
        {
                const std::string &l_ref = (a_ref->*converter)(a_msg, a_field, i_f);
                l_arr.PushBack(rapidjson::Value(l_ref.data(),
                                                l_ref.length(),
                                                a_alx).Move(),
                a_alx);
        }
        ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(), l_arr, a_alx);
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Convert a repeated field to json for a message type.
//! \return:  TODO
//! \param:   reflection the reflection interface for the message
//! \param:   field the field descriptor for the field we are converting
//! \param:   message the message being converted
//! \param:   value the value to store the converted data
//! ----------------------------------------------------------------------------
static int32_t convert_repeated_message_field(rapidjson::Value &ao_val,
                                              rapidjson::Document::AllocatorType& a_alx,
                                              const google::protobuf::Reflection* a_ref,
                                              const google::protobuf::FieldDescriptor* a_field,
                                              const google::protobuf::Message& a_msg)
{
        // Add array object...
        rapidjson::Value l_arr(rapidjson::kArrayType);
        for (int i_f = 0; i_f < a_ref->FieldSize(a_msg, a_field); ++i_f)
        {
                int32_t l_s;
                rapidjson::Value l_val;
                l_s = convert_to_json(l_val, a_alx, a_ref->GetRepeatedMessage(a_msg, a_field, i_f));
                if(l_s != JSPB_OK)
                {
                        return JSPB_ERROR;
                }
                l_arr.PushBack(l_val, a_alx);
        }
        ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(), l_arr, a_alx);
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Convert a repeated field to json for an enum type.
//! \return:  TODO
//! \param:   reflection the reflection interface for the message
//! \param:   field the field descriptor for the field we are converting
//! \param:   message the message being converted
//! \param:   value the value to store the converted data
//! ----------------------------------------------------------------------------
static int32_t convert_repeated_enum_field(rapidjson::Value &ao_val,
                                           rapidjson::Document::AllocatorType& a_alx,
                                           const google::protobuf::Reflection* a_ref,
                                           const google::protobuf::FieldDescriptor* a_field,
                                           const google::protobuf::Message& a_msg)
{
        // Add array object...
        rapidjson::Value l_arr(rapidjson::kArrayType);
        for (int i_f = 0; i_f < a_ref->FieldSize(a_msg, a_field); ++i_f)
        {
                l_arr.PushBack(rapidjson::Value(a_ref->GetRepeatedEnum(a_msg, a_field, i_f)->name().c_str(), a_alx).Move(),
                               a_alx);
                // TODO Error checking...
        }
        ao_val.AddMember(rapidjson::Value(a_field->name().c_str(), a_alx).Move(), l_arr, a_alx);
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Convert a repeated field to json.
//! \return:  TODO
//! \param:   reflection the reflection interface for the message
//! \param:   field the field descriptor for the field we are converting
//! \param:   message the message being converted
//! \param:   value the value to store the converted data
//! ----------------------------------------------------------------------------
static int32_t convert_repeated_field(rapidjson::Value &ao_val,
                                      rapidjson::Document::AllocatorType& a_alx,
                                      const google::protobuf::Reflection* a_ref,
                                      const google::protobuf::FieldDescriptor* a_field,
                                      const google::protobuf::Message& a_msg)
{
        int32_t l_s = JSPB_OK;
        switch (a_field->type())
        {
        case google::protobuf::FieldDescriptor::TYPE_DOUBLE:
        {
                l_s = convert_repeated_field<double>(ao_val,
                                                     a_alx,
                                                     a_ref,
                                                     &google::protobuf::Reflection::GetRepeatedUInt64,
                                                     a_field,
                                                     a_msg);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_FLOAT:
        {
                l_s = convert_repeated_field<double>(ao_val,
                                                     a_alx,
                                                     a_ref,
                                                     &google::protobuf::Reflection::GetRepeatedFloat,
                                                     a_field,
                                                     a_msg);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_INT64:
        case google::protobuf::FieldDescriptor::TYPE_SFIXED64:
        case google::protobuf::FieldDescriptor::TYPE_SINT64:
        {
                l_s = convert_repeated_field<int64_t>(ao_val,
                                                      a_alx,
                                                      a_ref,
                                                      &google::protobuf::Reflection::GetRepeatedInt64,
                                                      a_field,
                                                      a_msg);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_UINT64:
        case google::protobuf::FieldDescriptor::TYPE_FIXED64:
        {
                l_s = convert_repeated_field<uint64_t>(ao_val,
                                                       a_alx,
                                                       a_ref,
                                                       &google::protobuf::Reflection::GetRepeatedUInt64,
                                                       a_field,
                                                       a_msg);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_INT32:
        case google::protobuf::FieldDescriptor::TYPE_SFIXED32:
        case google::protobuf::FieldDescriptor::TYPE_SINT32:
        {
                l_s = convert_repeated_field<int32_t>(ao_val,
                                                      a_alx,
                                                      a_ref,
                                                      &google::protobuf::Reflection::GetRepeatedInt32,
                                                      a_field,
                                                      a_msg);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_FIXED32:
        case google::protobuf::FieldDescriptor::TYPE_UINT32:
        {
                l_s = convert_repeated_field<uint32_t>(ao_val,
                                                       a_alx,
                                                       a_ref,
                                                       &google::protobuf::Reflection::GetRepeatedUInt32,
                                                       a_field,
                                                       a_msg);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_BOOL:
        {
                l_s = convert_repeated_field<bool>(ao_val,
                                                   a_alx,
                                                   a_ref,
                                                   &google::protobuf::Reflection::GetRepeatedBool,
                                                   a_field,
                                                   a_msg);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_STRING:
        {
                l_s = convert_repeated_field_str(ao_val,
                                                 a_alx,
                                                 a_ref,
                                                 &google::protobuf::Reflection::GetRepeatedString,
                                                 a_field,
                                                 a_msg);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_GROUP:
        {
                JSPB_PERROR("group type not supported for field '%s'", a_field->full_name().c_str());
                return JSPB_ERROR;
        }
        case google::protobuf::FieldDescriptor::TYPE_MESSAGE:
        {
                convert_repeated_message_field(ao_val,
                                               a_alx,
                                               a_ref,
                                               a_field,
                                               a_msg);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_BYTES:
        {
                l_s = convert_repeated_field_str(ao_val,
                                                 a_alx,
                                                 a_ref,
                                                 &google::protobuf::Reflection::GetRepeatedString,
                                                 a_field,
                                                 a_msg);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_ENUM:
        {
                l_s = convert_repeated_enum_field(ao_val,
                                                  a_alx,
                                                  a_ref,
                                                  a_field,
                                                  a_msg);
                break;
        }
        default:
        {
                JSPB_PERROR("unknown type in field: '%s': %d", a_field->full_name().c_str(), a_field->type());
                return JSPB_ERROR;
        }
        }
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details: Update a field within a message from a given json object,
//!           for many types of values.
//! \return:  TODO
//! \param:   reflection the reflection interface for the message
//! \param:   field the field descriptor for the field we are updating
//! \param:   updater the method to use to update the field
//! \param:   value the value to get the information from
//! \param:   access the method used to get the value from the json object
//! \param:   checker the method used to check that the json type is correct
//! \param:   message the message being updated
//! ----------------------------------------------------------------------------
template <typename F1, typename F2, typename F3>
static int32_t update_field(google::protobuf::Message& ao_msg,
                            const google::protobuf::Reflection* a_ref,
                            const google::protobuf::FieldDescriptor* a_field,
                            F1 a_updater,
                            const rapidjson::Value &a_val,
                            F2 a_accessor,
                            F3 a_checker,
                            const char *a_type)
{
        JSPB_TRACE("update_field\n");
        if (!((a_val.*a_checker)()))
        {
                JSPB_PERROR("expecting type: %s for field: '%s'", a_field->type_name(), a_field->full_name().c_str());
                return JSPB_ERROR;
        }
        (a_ref->*a_updater)(&ao_msg, a_field, (a_val.*a_accessor)());
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Update single enum field within message from json object.
//! \return:  TODO
//! \param:   reflection the reflection interface for the message
//! \param:   field the field descriptor for the field we are updating
//! \param:   value the value to get the information from
//! \param:   message the message being updated
//! ----------------------------------------------------------------------------
template <typename F1>
static int32_t update_enum_field(google::protobuf::Message& ao_msg,
                                 const google::protobuf::Reflection* a_ref,
                                 const google::protobuf::EnumDescriptor* a_des,
                                 const google::protobuf::FieldDescriptor* a_field,
                                 F1 a_updater,
                                 const rapidjson::Value &a_val)
{
        if (!a_val.IsString())
        {
                JSPB_PERROR("expecting string (enum) for field '%s'", a_field->full_name().c_str());
                return JSPB_ERROR;
        }
        const google::protobuf::EnumValueDescriptor* enumValueDescriptor = a_des->FindValueByName(a_val.GetString());
        if (0 == enumValueDescriptor)
        {
                JSPB_PERROR("unknown enum for field ' '%s': %s", a_field->full_name().c_str(), a_val.GetString());
                return JSPB_ERROR;
        }
        (a_ref->*a_updater)(&ao_msg, a_field, enumValueDescriptor);
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Update single field within message from json object.
//! \return:  TODO
//! \param:   reflection the reflection interface for the message
//! \param:   field the field descriptor for the field we are updating
//! \param:   value the value to get the information from
//! \param:   message the message being updated
//! ----------------------------------------------------------------------------
static int32_t update_single_field(google::protobuf::Message& ao_msg,
                                   const google::protobuf::Reflection* a_ref,
                                   const google::protobuf::Descriptor* a_des,
                                   const google::protobuf::FieldDescriptor* a_field,
                                   const rapidjson::Value &a_val)
{
        JSPB_TRACE("update_single_field\n");
        int32_t l_s = JSPB_OK;
        switch (a_field->type())
        {
        case google::protobuf::FieldDescriptor::TYPE_DOUBLE:
        {
                JSPB_TRACE("case: double\n");
                l_s = update_field(ao_msg,
                                   a_ref,
                                   a_field,
                                   &google::protobuf::Reflection::SetDouble,
                                   a_val,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::GetDouble,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::IsNumber,
                                   "float");
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_FLOAT:
        {
                JSPB_TRACE("case: float\n");
                l_s = update_field(ao_msg,
                                   a_ref,
                                   a_field,
                                   &google::protobuf::Reflection::SetFloat,
                                   a_val,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::GetFloat,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::IsNumber,
                                   "float");
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_INT64:
        case google::protobuf::FieldDescriptor::TYPE_SFIXED64:
        case google::protobuf::FieldDescriptor::TYPE_SINT64:
        {
                JSPB_TRACE("case: int64\n");
                l_s = update_field(ao_msg,
                                   a_ref,
                                   a_field,
                                   &google::protobuf::Reflection::SetInt64,
                                   a_val,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::GetInt64,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::IsInt64,
                                   "int");
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_UINT64:
        case google::protobuf::FieldDescriptor::TYPE_FIXED64:
        {
                JSPB_TRACE("case: uint64\n");
                l_s = update_field(ao_msg,
                                   a_ref,
                                   a_field,
                                   &google::protobuf::Reflection::SetUInt64,
                                   a_val,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::GetUint64,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::IsUint64,
                                   "unsigned int");
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_INT32:
        case google::protobuf::FieldDescriptor::TYPE_SFIXED32:
        case google::protobuf::FieldDescriptor::TYPE_SINT32:
        {
                JSPB_TRACE("case: int32\n");
                l_s = update_field(ao_msg,
                                   a_ref,
                                   a_field,
                                   &google::protobuf::Reflection::SetInt32,
                                   a_val,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::GetInt,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::IsInt,
                                   "int");
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_FIXED32:
        case google::protobuf::FieldDescriptor::TYPE_UINT32:
        {
                JSPB_TRACE("case: uint32\n");
                l_s = update_field(ao_msg,
                                   a_ref,
                                   a_field,
                                   &google::protobuf::Reflection::SetUInt32,
                                   a_val,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::GetUint,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::IsUint,
                                   "unsigned int");
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_BOOL:
        {
                JSPB_TRACE("case: bool\n");
                l_s = update_field(ao_msg,
                                   a_ref,
                                   a_field,
                                   &google::protobuf::Reflection::SetBool,
                                   a_val,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::GetBool,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::IsBool,
                                   "boolean");
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_STRING:
        {
                JSPB_TRACE("case: string\n");
                l_s = update_field(ao_msg,
                                   a_ref,
                                   a_field,
                                   &google::protobuf::Reflection::SetString,
                                   a_val,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::GetString,
                                   &rapidjson::GenericValue<rapidjson::UTF8<> >::IsString,
                                   "string");
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_GROUP:
        {
                JSPB_TRACE("case: group\n");
                JSPB_PERROR("group type not supported for field '%s'", a_field->full_name().c_str());
                return JSPB_ERROR;
        }
        case google::protobuf::FieldDescriptor::TYPE_MESSAGE:
        {
                if (!a_val.IsObject())
                {
                        JSPB_PERROR("expected field '%s' to be an object",
                                    a_field->full_name().c_str());
                        return JSPB_ERROR;
                }
                JSPB_TRACE("case: message\n");
                l_s = update_from_json(*(a_ref->MutableMessage(&ao_msg, a_field)),
                                       a_val);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_BYTES:
        {
                JSPB_TRACE("case: bytes\n");
                JSPB_PERROR("binary type not supported for field '%s'", a_field->full_name().c_str());
                return JSPB_ERROR;
        }
        case google::protobuf::FieldDescriptor::TYPE_ENUM:
        {
                JSPB_TRACE("case: enum\n");
                l_s = update_enum_field(ao_msg,
                                        a_ref,
                                        a_field->enum_type(),
                                        a_field,
                                        &google::protobuf::Reflection::SetEnum,
                                        a_val);
                break;
        }
        default:
        {
                JSPB_TRACE("case: default\n");
                JSPB_PERROR("unknown type in field: '%s': %d", a_field->full_name().c_str(), a_field->type());
                return JSPB_ERROR;
        }
        }
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details: Update a repeated field within a message from a given json object,
//!           for many types of values.
//! \return:  TODO
//! \param:   reflection the reflection interface for the message
//! \param:   field the field descriptor for the field we are updating
//! \param:   updater the method to use to update the field
//! \param:   value the value to get the information from
//! \param:   access the method used to get the value from the json object
//! \param:   checker the method used to check that the json type is correct
//! \param:   message the message being updated
//! ----------------------------------------------------------------------------
template <typename F1, typename F2, typename F3>
static int32_t update_repeated_field(google::protobuf::Message& ao_msg,
                                     const google::protobuf::Reflection* a_ref,
                                     const google::protobuf::FieldDescriptor* a_field,
                                     F1 a_updater,
                                     const rapidjson::Value &a_val,
                                     F2 a_accessor,
                                     F3 a_checker)
{
        for(rapidjson::Value::ConstValueIterator i_m = a_val.Begin();
            i_m != a_val.End();
            ++i_m)
        {
                int32_t l_s;
                l_s = update_field(ao_msg,
                                   a_ref,
                                   a_field,
                                   a_updater,
                                   *i_m,
                                   a_accessor,
                                   a_checker,
                                   "repeated");
                if(l_s != JSPB_OK)
                {
                        return JSPB_ERROR;
                }
        }
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Update repeated message field within message from json object.
//! \return:  TODO
//! \param:   reflection the reflection interface for the message
//! \param:   field the field descriptor for the field we are updating
//! \param:   value the value to get the information from
//! \param:   message the message being updated
//! ----------------------------------------------------------------------------
static int32_t update_repeated_message_field(google::protobuf::Message& ao_msg,
                                             const google::protobuf::Reflection* a_ref,
                                             const google::protobuf::FieldDescriptor* a_field,
                                             const rapidjson::Value &a_val)
{
        JSPB_TRACE("update_repeated_message_field ...\n");
        for(rapidjson::Value::ConstValueIterator i_m = a_val.Begin();
            i_m != a_val.End();
            ++i_m)
        {
                google::protobuf::Message* l_child = a_ref->AddMessage(&ao_msg, a_field);
                int32_t l_s;
                l_s = update_from_json(*l_child, *i_m);
                if(l_s != JSPB_OK)
                {
                        return JSPB_ERROR;
                }
        }
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Update repeated enum field within message from json object.
//! \return:  TODO
//! \param:   reflection the reflection interface for the message
//! \param:   field the field descriptor for the field we are updating
//! \param:   value the value to get the information from
//! \param:   message the message being updated
//! ----------------------------------------------------------------------------
static int32_t update_repeated_enum_field(google::protobuf::Message& ao_msg,
                                          const google::protobuf::Reflection* a_ref,
                                          const google::protobuf::Descriptor* a_des,
                                          const google::protobuf::FieldDescriptor* a_field,
                                          const rapidjson::Value &a_val)
{
        for(rapidjson::Value::ConstValueIterator i_m = a_val.Begin();
            i_m != a_val.End();
            ++i_m)
        {
                int32_t l_s;
                l_s = update_enum_field(ao_msg,
                                        a_ref,
                                        a_field->enum_type(),
                                        a_field,
                                        &google::protobuf::Reflection::AddEnum,
                                        *i_m);
                if(l_s != JSPB_OK)
                {
                        return JSPB_ERROR;
                }
        }
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Update repeated field within message from json object.
//! \return:  TODO
//! \param:   reflection the reflection interface for the message
//! \param:   field the field descriptor for the field we are updating
//! \param:   value the value to get the information from
//! \param:   message the message being updated
//! ----------------------------------------------------------------------------
static int32_t update_repeated_field(google::protobuf::Message& ao_msg,
                                     const google::protobuf::Reflection* a_ref,
                                     const google::protobuf::Descriptor* a_des,
                                     const google::protobuf::FieldDescriptor* a_field,
                                     const rapidjson::Value &a_val)
{
        JSPB_TRACE("update_repeated_field ...\n");
        int32_t l_s;
        switch (a_field->type())
        {
        case google::protobuf::FieldDescriptor::TYPE_DOUBLE:
        {
                JSPB_TRACE("case: double\n");
                l_s = update_repeated_field(ao_msg,
                                            a_ref,
                                            a_field,
                                            &google::protobuf::Reflection::AddDouble,
                                            a_val,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::GetDouble,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::IsNumber);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_FLOAT:
        {
                JSPB_TRACE("case: float\n");
                l_s = update_repeated_field(ao_msg,
                                            a_ref,
                                            a_field,
                                            &google::protobuf::Reflection::AddFloat,
                                            a_val,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::GetFloat,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::IsNumber);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_INT64:
        case google::protobuf::FieldDescriptor::TYPE_SFIXED64:
        case google::protobuf::FieldDescriptor::TYPE_SINT64:
        {
                JSPB_TRACE("case: int64\n");
                l_s = update_repeated_field(ao_msg,
                                            a_ref,
                                            a_field,
                                            &google::protobuf::Reflection::AddInt64,
                                            a_val,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::GetInt64,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::IsInt64);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_UINT64:
        case google::protobuf::FieldDescriptor::TYPE_FIXED64:
        {
                JSPB_TRACE("case: uint64\n");
                l_s = update_repeated_field(ao_msg,
                                            a_ref,
                                            a_field,
                                            &google::protobuf::Reflection::AddUInt64,
                                            a_val,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::GetUint64,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::IsUint64);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_INT32:
        case google::protobuf::FieldDescriptor::TYPE_SFIXED32:
        case google::protobuf::FieldDescriptor::TYPE_SINT32:
        {
                JSPB_TRACE("case: int32\n");
                l_s = update_repeated_field(ao_msg,
                                            a_ref,
                                            a_field,
                                            &google::protobuf::Reflection::AddInt32,
                                            a_val,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::GetInt,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::IsInt);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_FIXED32:
        case google::protobuf::FieldDescriptor::TYPE_UINT32:
        {
                JSPB_TRACE("case: uint32\n");
                l_s = update_repeated_field(ao_msg,
                                            a_ref,
                                            a_field,
                                            &google::protobuf::Reflection::AddUInt32,
                                            a_val,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::GetUint,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::IsUint);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_BOOL:
        {
                JSPB_TRACE("case: bool\n");
                l_s = update_repeated_field(ao_msg,
                                            a_ref,
                                            a_field,
                                            &google::protobuf::Reflection::AddBool,
                                            a_val,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::GetBool,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::IsBool);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_STRING:
        {
                JSPB_TRACE("case: string\n");
                l_s = update_repeated_field(ao_msg,
                                            a_ref,
                                            a_field,
                                            &google::protobuf::Reflection::AddString,
                                            a_val,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::GetString,
                                            &rapidjson::GenericValue<rapidjson::UTF8<> >::IsString);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_GROUP:
        {
                JSPB_PERROR("group type not supported for field '%s'", a_field->full_name().c_str());
                return JSPB_ERROR;
        }
        case google::protobuf::FieldDescriptor::TYPE_MESSAGE:
        {
                if (!a_val.IsArray())
                {
                        JSPB_PERROR("expected field '%s' to be an array of objects",
                                    a_field->full_name().c_str());
                        return JSPB_ERROR;
                }
                JSPB_TRACE("case: message\n");
                l_s = update_repeated_message_field(ao_msg,
                                                    a_ref,
                                                    a_field,
                                                    a_val);
                break;
        }
        case google::protobuf::FieldDescriptor::TYPE_BYTES:
        {
                JSPB_PERROR("binary type not supported for field '%s'", a_field->full_name().c_str());
                return JSPB_ERROR;
        }
        case google::protobuf::FieldDescriptor::TYPE_ENUM:
        {
                JSPB_TRACE("case: enum\n");
                l_s = update_repeated_enum_field(ao_msg,
                                                 a_ref,
                                                 a_des,
                                                 a_field,
                                                 a_val);
                break;
        }
        default:
        {
                JSPB_PERROR("unknown type in field: '%s': %d", a_field->full_name().c_str(), a_field->type());
                return JSPB_ERROR;
        }
        }
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t convert_to_json(rapidjson::Value &ao_val,
                        rapidjson::Document::AllocatorType &a_alx,
                        const google::protobuf::Message& a_msg)
{
        rapidjson::Value &l_v = ao_val.SetObject();
        const google::protobuf::Reflection* l_ref = a_msg.GetReflection();
        std::vector<const google::protobuf::FieldDescriptor*> l_fs;
        l_ref->ListFields(a_msg, &l_fs);
        for (std::vector<const google::protobuf::FieldDescriptor*>::const_iterator i_f = l_fs.begin();
             i_f != l_fs.end();
             ++i_f)
        {
                const google::protobuf::FieldDescriptor* l_f = *i_f;
                switch (l_f->label())
                {
                case google::protobuf::FieldDescriptor::LABEL_OPTIONAL:
                case google::protobuf::FieldDescriptor::LABEL_REQUIRED:
                {
                        int32_t l_s = JSPB_OK;
                        l_s = convert_single_field(l_v, a_alx, l_ref, l_f, a_msg);
                        if(l_s != JSPB_OK)
                        {
                                return JSPB_ERROR;
                        }
                        break;
                }
                case google::protobuf::FieldDescriptor::LABEL_REPEATED:
                {
                        int32_t l_s = JSPB_OK;
                        l_s = convert_repeated_field(l_v, a_alx, l_ref, l_f, a_msg);
                        if(l_s != JSPB_OK)
                        {
                                return JSPB_ERROR;
                        }
                        break;
                }
                default:
                {
                        JSPB_PERROR("unknown label in field '%s': %d", l_f->full_name().c_str(), l_f->label());
                        return JSPB_ERROR;
                }
                }
        }
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Convert a protobuf message to a json object, storing
//!           the result in a rapidjson::Document object.
//! \return:  TODO
//! \param:   msg the protobuf message to convert
//! \param:   value json object to hold the converted value
//! ----------------------------------------------------------------------------
int32_t convert_to_json(rapidjson::Document& ao_js,
                        const google::protobuf::Message& a_msg)
{
        rapidjson::Document::AllocatorType& l_alx = ao_js.GetAllocator();
        rapidjson::Value &l_v = ao_js.SetObject();
        const google::protobuf::Reflection* l_ref = a_msg.GetReflection();
        std::vector<const google::protobuf::FieldDescriptor*> l_fs;
        l_ref->ListFields(a_msg, &l_fs);
        for (std::vector<const google::protobuf::FieldDescriptor*>::const_iterator i_f = l_fs.begin();
             i_f != l_fs.end();
             ++i_f)
        {
                const google::protobuf::FieldDescriptor* l_f = *i_f;
                switch (l_f->label())
                {
                case google::protobuf::FieldDescriptor::LABEL_OPTIONAL:
                case google::protobuf::FieldDescriptor::LABEL_REQUIRED:
                {
                        int32_t l_s = JSPB_OK;
                        l_s = convert_single_field(l_v, l_alx, l_ref, l_f, a_msg);
                        if(l_s != JSPB_OK)
                        {
                                return JSPB_ERROR;
                        }
                        break;
                }
                case google::protobuf::FieldDescriptor::LABEL_REPEATED:
                {
                        int32_t l_s = JSPB_OK;
                        l_s = convert_repeated_field(l_v, l_alx, l_ref, l_f, a_msg);
                        if(l_s != JSPB_OK)
                        {
                                return JSPB_ERROR;
                        }
                        break;
                }
                default:
                {
                        JSPB_PERROR("unknown label in field '%s': %d", l_f->full_name().c_str(), l_f->label());
                        return JSPB_ERROR;
                }
                }
        }
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Convert a protobuf message to a json object, storing the
//!           result in a std::string.
//! \return:  TODO
//! \param:   msg the protobuf message to convert
//! \param:   value json object to hold the converted value
//! ----------------------------------------------------------------------------
int32_t convert_to_json(std::string& ao_str,
                        const google::protobuf::Message& a_msg)
{
        // put on the heap...
        rapidjson::Document *l_js = new rapidjson::Document();
        rapidjson::StringBuffer l_strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> l_js_writer(l_strbuf);
        int32_t l_s;
        l_s = convert_to_json(*l_js, a_msg);
        if(l_s != JSPB_OK)
        {
                goto done;
        }
        // write back to str
        (*l_js).Accept(l_js_writer);
        // TODO -can eliminate copy here???
        ao_str = l_strbuf.GetString();
done:
        if(l_js)
        {
                delete l_js;
                l_js = NULL;
        }
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t update_from_json(google::protobuf::Message& ao_msg,
                         const rapidjson::Value &a_val)
{
        JSPB_TRACE("update_from_json ...\n");
        if(!a_val.IsObject())
        {
               JSPB_PERROR("error json not an object");
               return JSPB_ERROR;
        }
        // Walk through the json members and insert them into the protobuf.
        const google::protobuf::Reflection* l_ref = ao_msg.GetReflection();
        const google::protobuf::Descriptor* l_des = ao_msg.GetDescriptor();
        // ---------------------------------------
        // Iterate over objects...
        // ---------------------------------------
        JSPB_TRACE("iterating over members\n");
        for (rapidjson::Value::ConstMemberIterator i_m = a_val.MemberBegin();
             i_m != a_val.MemberEnd();
             ++i_m)
        {
                const char *i_k = i_m->name.GetString();
                JSPB_TRACE("member: %s\n", i_k);
                // -------------------------------
                // "user-agent" hack...
                // TODO fix in json with "user_agent"
                // -------------------------------
                if(strncmp(i_k, "user-agent", strlen("user-agent")) == 0)
                {
                        i_k = "user_agent";
                }
                const google::protobuf::FieldDescriptor* l_f = l_des->FindFieldByName(i_k);
                if (0 == l_f)
                {
                        JSPB_PERROR("json field '%s' not found in message", i_k);
                        return JSPB_ERROR;
                }
                // ---------------------------------------------------
                // TODO REMOVE!!!
                // response_headers hack
                // ---------------------------------------------------
                // original looks like:
                // ...
                // "response_headers": {
                //   "Custom Header A": "Value 1"
                // }
                // ...
                // convert to
                // ...
                // "response_headers": [
                //   {"key": "Custom Header A", "value": "Value 1"}
                // ]
                // ...
                // ---------------------------------------------------
                if((strcmp(i_k, "response_headers") == 0) &&
                   (a_val.HasMember("response_headers") &&
                    a_val["response_headers"].IsObject()))
                {
                        JSPB_TRACE("performing response_headers hack :(\n");
                        // Create object in place
                        rapidjson::Document l_js_doc;
                        l_js_doc.SetObject();
                        rapidjson::Value l_js_array(rapidjson::kArrayType);
                        rapidjson::Document::AllocatorType& l_js_allocator = l_js_doc.GetAllocator();
                        for (rapidjson::Value::ConstMemberIterator i_m = a_val["response_headers"].MemberBegin();
                             i_m != a_val["response_headers"].MemberEnd();
                             ++i_m)
                        {
                                rapidjson::Value l_obj;
                                l_obj.SetObject();
                                l_obj.AddMember("key",
                                                rapidjson::Value(i_m->name.GetString(), l_js_allocator).Move(),
                                                l_js_allocator);
                                l_obj.AddMember("value",
                                                rapidjson::Value(i_m->value.GetString(), l_js_allocator).Move(),
                                                l_js_allocator);
                                l_js_array.PushBack(l_obj, l_js_allocator);
                        }
                        l_js_doc.AddMember("response_headers", l_js_array, l_js_allocator);
                        JSPB_TRACE("response_headers hack: update repeated field\n");
                        // the json array will completely replace this field
                        l_ref->ClearField(&ao_msg, l_f);
                        int32_t l_s = JSPB_OK;
                        JSPB_TRACE("update_repeated_field\n");
                        l_s = update_repeated_field(ao_msg,
                                                    l_ref,
                                                    l_des,
                                                    l_f,
                                                    l_js_doc["response_headers"]);
                        JSPB_TRACE("response_headers hack: update repeated field -done\n");
                        if(l_s != JSPB_OK)
                        {
                                return JSPB_ERROR;
                        }
                        continue;
                }
                //const rapidjson::GenericValue<rapidjson::UTF8<> >::ConstObject &i_v = i_m->value.GetObject();
                const rapidjson::Value &i_v = i_m->value;
                if(i_v.IsNull())
                {
                        JSPB_TRACE("member: %s NULL -skipping\n", i_k);
                        continue;
                }
                switch (l_f->label())
                {
                case google::protobuf::FieldDescriptor::LABEL_OPTIONAL:
                case google::protobuf::FieldDescriptor::LABEL_REQUIRED:
                {
                        JSPB_TRACE("update_single_field\n");
                        int32_t l_s = JSPB_OK;
                        l_s = update_single_field(ao_msg,
                                                  l_ref,
                                                  l_des,
                                                  l_f,
                                                  i_v);
                        if(l_s != JSPB_OK)
                        {
                                return JSPB_ERROR;
                        }
                        break;
                }
                case google::protobuf::FieldDescriptor::LABEL_REPEATED:
                {
                        // make sure the json value is an array
                        if(!i_m->value.IsArray())
                        {
                                JSPB_PERROR("expecting json array for field '%s'", l_f->full_name().c_str());
                                return JSPB_ERROR;
                        }
                        // the json array will completely replace this field
                        l_ref->ClearField(&ao_msg, l_f);
                        JSPB_TRACE("update_repeated_field\n");
                        int32_t l_s = JSPB_OK;
                        l_s = update_repeated_field(ao_msg,
                                                    l_ref,
                                                    l_des,
                                                    l_f,
                                                    i_v);
                        if(l_s != JSPB_OK)
                        {
                                return JSPB_ERROR;
                        }
                        break;
                }
                default:
                {
                        JSPB_PERROR("unknown label in field '%s': %d", l_f->full_name().c_str(), l_f->label());
                        return JSPB_ERROR;
                }
                }
        }
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Convert a json object to a protobuf message, reading the
//!           json value from a Json::Value object.
//! \return:  TODO
//! \param:   value json object to convert
//! \param:   message protobuf message to hold the converted value
//! ----------------------------------------------------------------------------
int32_t update_from_json(google::protobuf::Message& ao_msg,
                         const rapidjson::Document& a_js)
{
        JSPB_TRACE("update_from_json ...\n");
        if(!a_js.IsObject())
        {
                JSPB_PERROR("error json not an object");
                return JSPB_ERROR;
        }
        // Walk through the json members and insert them into the protobuf.
        const google::protobuf::Reflection* l_ref = ao_msg.GetReflection();
        const google::protobuf::Descriptor* l_des = ao_msg.GetDescriptor();
        // ---------------------------------------
        // Iterate over objects...
        // ---------------------------------------
        JSPB_TRACE("iterating over members\n");
        for (rapidjson::Value::ConstMemberIterator i_m = a_js.MemberBegin();
             i_m != a_js.MemberEnd();
             ++i_m)
        {
                const char *i_k = i_m->name.GetString();
                JSPB_TRACE("member: %s\n", i_k);
                if(i_m->value.IsNull())
                {
                        JSPB_TRACE("member: %s NULL -skipping\n", i_k);
                        continue;
                }
                const google::protobuf::FieldDescriptor* l_f = l_des->FindFieldByName(i_k);
                if (0 == l_f)
                {
                        JSPB_PERROR("json field '%s' not found in message", i_k);
                        return JSPB_ERROR;
                }
                //const rapidjson::GenericValue<rapidjson::UTF8<> >::ConstObject &i_v = i_m->value.GetObject();
                const rapidjson::Value &i_v = i_m->value;
                switch (l_f->label())
                {
                case google::protobuf::FieldDescriptor::LABEL_OPTIONAL:
                {
                        JSPB_TRACE("case: optional\n");
                        // fall thru
                }
                case google::protobuf::FieldDescriptor::LABEL_REQUIRED:
                {
                        JSPB_TRACE("case: required\n");
                        JSPB_TRACE("update_single_field\n");
                        int32_t l_s = JSPB_OK;
                        l_s = update_single_field(ao_msg,
                                                  l_ref,
                                                  l_des,
                                                  l_f,
                                                  i_v);
                        if(l_s != JSPB_OK)
                        {
                                return JSPB_ERROR;
                        }
                        break;
                }
                case google::protobuf::FieldDescriptor::LABEL_REPEATED:
                {
                        JSPB_TRACE("case: repeated\n");
                        // make sure the json value is an array
                        if(!i_m->value.IsArray())
                        {
                                JSPB_PERROR("expecting json array for field '%s'", l_f->full_name().c_str());
                                return JSPB_ERROR;
                        }
                        // the json array will completely replace this field
                        l_ref->ClearField(&ao_msg, l_f);
                        JSPB_TRACE("update_repeated_field\n");
                        int32_t l_s = JSPB_OK;
                        l_s = update_repeated_field(ao_msg,
                                                    l_ref,
                                                    l_des,
                                                    l_f,
                                                    i_v);
                        if(l_s != JSPB_OK)
                        {
                                return JSPB_ERROR;
                        }
                        break;
                }
                default:
                {
                        JSPB_PERROR("unknown label in field '%s': %d", l_f->full_name().c_str(), l_f->label());
                        return JSPB_ERROR;
                }
                }
        }
        return JSPB_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Convert a json object to a protobuf message, reading the
//!           json value from a std::string.
//! \return:  TODO
//! \param:   value json object to convert
//! \param:   message protobuf message to hold the converted value
//! ----------------------------------------------------------------------------
int32_t update_from_json(google::protobuf::Message& ao_msg,
                         const char *a_buf,
                         uint32_t a_len)
{
        // put on the heap...
        rapidjson::Document *l_js = new rapidjson::Document();
        JSPB_TRACE("json parse ...\n");
        rapidjson::ParseResult l_ok;
        l_ok = l_js->Parse(a_buf, a_len);
        if (!l_ok)
        {
                JSPB_PERROR("JSON parse error: %s (%d)\n", rapidjson::GetParseError_En(l_ok.Code()), (int)l_ok.Offset());
                if(l_js)
                {
                        delete l_js;
                        l_js = NULL;
                }
                return JSPB_ERROR;
        }
        if(!l_js->IsObject())
        {
                rapidjson::ParseErrorCode l_code = l_js->GetParseError();
                JSPB_PERROR("error parsing json Not an object -code: %d -type: %d", l_code, l_js->GetType());
                if(l_js)
                {
                        delete l_js;
                        l_js = NULL;
                }
                return JSPB_ERROR;
        }
        JSPB_TRACE("json parse ok\n");
        int32_t l_s;
        l_s = update_from_json(ao_msg, *l_js);
        if(l_js)
        {
                delete l_js;
                l_js = NULL;
        }
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details: Convert a json object to a protobuf message, reading the
//!           json value from a std::string.
//! \return:  TODO
//! \param:   value json object to convert
//! \param:   message protobuf message to hold the converted value
//! ----------------------------------------------------------------------------
int32_t update_from_json(google::protobuf::Message& ao_msg,
                         const std::string& a_str)
{
        return update_from_json(ao_msg, a_str.c_str(), a_str.length());
}
//! ----------------------------------------------------------------------------
//! \details: Get last error
//! \return:  Last error reason
//! ----------------------------------------------------------------------------
const char * get_jspb_err_msg(void)
{
        return s_err_msg;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void set_trace(bool a_val)
{
        s_trace = a_val;
}
} // namespace
